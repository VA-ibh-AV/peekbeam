use std::{
    cell::RefCell,
    collections::HashMap,
    mem::size_of,
    path::Path,
    rc::Rc,
    time::Duration,
};

use anyhow::{Context, anyhow};
use aya::{
    maps::{HashMap as BpfHashMap, RingBuf},
    programs::TracePoint,
};
use clap::{ArgGroup, Parser};
use log::debug;
use peekbeam_common::{
    EventKind, FileEvent, FileEventKind, MemEvent, MemEventKind, NetEvent, NetEventKind,
    SyscallEvent, TCP_CLOSE,
};

mod container;
mod file_table;
mod headless;
mod mem_stats;
mod net_table;
mod pod;
mod signals;
mod summary;
mod syscall_table;
mod tui;

/// Live, low-overhead syscall visibility for one target: a PID, a container,
/// or (untested against a real cluster — see `pod.rs`) a Kubernetes pod.
#[derive(Parser)]
#[command(name = "peekbeam", version, about)]
#[command(group(ArgGroup::new("target").required(true).args(["pid", "container", "pod"])))]
struct Args {
    /// PID to trace.
    #[arg(long)]
    pid: Option<u32>,

    /// Container ID or name to trace (Docker only, cgroup v2 hosts only).
    #[arg(long)]
    container: Option<String>,

    /// Pod name to trace (Kubernetes; needs kubectl configured, and the pod
    /// scheduled on this node — see readme.md §3.1).
    #[arg(long)]
    pod: Option<String>,

    /// Namespace for --pod.
    #[arg(long, short = 'n', default_value = "default")]
    namespace: String,

    /// TUI refresh interval, in milliseconds. Also the streaming interval
    /// for --json without --duration.
    #[arg(long, default_value_t = 1000)]
    refresh_ms: u64,

    /// Structured (JSON) output instead of the interactive TUI. Without
    /// --duration, streams one JSON line per --refresh-ms until stopped.
    #[arg(long)]
    json: bool,

    /// Run for a fixed window (seconds), then print one final summary and
    /// exit, instead of the interactive TUI.
    #[arg(long)]
    duration: Option<u64>,
}

enum Target {
    Pid(u32),
    Container(container::ContainerTarget),
    Pod { name: String, inner: container::ContainerTarget },
}

impl Target {
    fn label(&self) -> String {
        match self {
            Target::Pid(pid) => format!("PID {pid}"),
            Target::Container(c) => {
                format!("container {} (cgroup {})", &c.full_id[..12.min(c.full_id.len())], c.cgroup_id)
            }
            Target::Pod { name, inner } => format!("pod {name} (cgroup {})", inner.cgroup_id),
        }
    }

    /// FR5.3 (memory panel): for `--pid`, that process's own memory, not
    /// whatever else happens to share its cgroup.
    fn memory_target(&self) -> mem_stats::MemoryTarget {
        match self {
            Target::Pid(pid) => mem_stats::MemoryTarget::Pid(*pid),
            Target::Container(c) => mem_stats::MemoryTarget::Cgroup(c.cgroup_path.clone()),
            Target::Pod { inner, .. } => mem_stats::MemoryTarget::Cgroup(inner.cgroup_path.clone()),
        }
    }
}

/// Aggregated stats for one syscall number, matched from enter/exit event pairs.
#[derive(Default, Clone, Copy)]
pub struct SyscallStats {
    pub count: u64,
    pub total_ns: u64,
}

impl SyscallStats {
    pub fn avg_ns(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.total_ns / self.count
        }
    }
}

pub type StatsMap = Rc<RefCell<HashMap<u64, SyscallStats>>>;

/// Identifies one TCP connection by its 4-tuple (FR3.3). IPv4 addresses are
/// stored in the first 4 bytes of `saddr`/`daddr`, matching `NetEvent`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub family: u16,
    pub sport: u16,
    pub dport: u16,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
}

/// Aggregated state for one connection (FR3.3/FR3.4).
#[derive(Default, Clone, Copy)]
pub struct ConnectionStats {
    pub state: u16,
    pub retransmits: u64,
}

pub type ConnMap = Rc<RefCell<HashMap<ConnectionKey, ConnectionStats>>>;

/// One open (or previously-open) file descriptor for the target (FR4.1/4.2).
#[derive(Clone)]
pub struct FileStats {
    pub path: String,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub closed: bool,
}

pub type FilesMap = Rc<RefCell<HashMap<(u32, i32), FileStats>>>;

/// Kernel allocation activity attributable to the target (FR5.1).
#[derive(Default, Clone, Copy)]
pub struct MemEventStats {
    pub alloc_count: u64,
    pub alloc_bytes: u64,
    pub free_count: u64,
}

pub type MemEventStatsCell = Rc<RefCell<MemEventStats>>;

/// FR8.1: fail with an actionable message instead of a raw kernel error when the
/// process lacks the privileges eBPF loading/attaching requires.
fn check_privileges() -> anyhow::Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        return Ok(());
    }

    let has = |cap: caps::Capability| caps::has_cap(None, caps::CapSet::Effective, cap).unwrap_or(false);
    if has(caps::Capability::CAP_BPF) && has(caps::Capability::CAP_PERFMON) {
        return Ok(());
    }

    Err(anyhow!(
        "peekbeam needs root, or CAP_BPF+CAP_PERFMON.\n\
         Run with sudo, or grant the capabilities to the binary:\n\
         \x20 sudo setcap cap_bpf,cap_perfmon+ep <path-to-peekbeam>"
    ))
}

/// FR1.4: fail clearly and immediately if the target PID can't be resolved.
fn check_target_exists(pid: u32) -> anyhow::Result<()> {
    if Path::new(&format!("/proc/{pid}")).exists() {
        Ok(())
    } else {
        Err(anyhow!("no such process: PID {pid} (checked /proc/{pid})"))
    }
}

/// Bump the memlock rlimit; needed on kernels that don't use memcg-based accounting
/// for eBPF map memory. See https://lwn.net/Articles/837122/.
fn raise_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("failed to raise RLIMIT_MEMLOCK, ret={ret}");
    }
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    let target = if let Some(pid) = args.pid {
        check_target_exists(pid)?;
        Target::Pid(pid)
    } else if let Some(container_id) = args.container.as_deref() {
        Target::Container(container::resolve(container_id)?)
    } else if let Some(pod_name) = args.pod.as_deref() {
        Target::Pod {
            name: pod_name.to_string(),
            inner: pod::resolve(pod_name, &args.namespace)?,
        }
    } else {
        unreachable!("clap requires exactly one of --pid/--container/--pod")
    };

    check_privileges()?;
    raise_memlock_rlimit();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/peekbeam"
    )))
    .context("loading eBPF bytecode")?;

    match &target {
        Target::Pid(pid) => {
            let mut pid_filter: BpfHashMap<_, u32, u8> = BpfHashMap::try_from(
                ebpf.map_mut("PID_FILTER")
                    .context("PID_FILTER map not found in eBPF object")?,
            )?;
            pid_filter.insert(*pid, 1u8, 0)?;
        }
        Target::Container(c) => {
            let mut cgroup_filter: BpfHashMap<_, u64, u8> = BpfHashMap::try_from(
                ebpf.map_mut("CGROUP_FILTER")
                    .context("CGROUP_FILTER map not found in eBPF object")?,
            )?;
            cgroup_filter.insert(c.cgroup_id, 1u8, 0)?;
        }
        Target::Pod { inner, .. } => {
            let mut cgroup_filter: BpfHashMap<_, u64, u8> = BpfHashMap::try_from(
                ebpf.map_mut("CGROUP_FILTER")
                    .context("CGROUP_FILTER map not found in eBPF object")?,
            )?;
            cgroup_filter.insert(inner.cgroup_id, 1u8, 0)?;
        }
    }

    for (category, prog_name) in [
        ("raw_syscalls", "sys_enter"),
        ("raw_syscalls", "sys_exit"),
        ("sock", "inet_sock_set_state"),
        ("tcp", "tcp_retransmit_skb"),
        ("kmem", "kmalloc"),
        ("kmem", "kfree"),
    ] {
        let program: &mut TracePoint = ebpf
            .program_mut(prog_name)
            .with_context(|| format!("program `{prog_name}` not found in eBPF object"))?
            .try_into()?;
        program.load()?;
        program
            .attach(category, prog_name)
            .with_context(|| format!("attaching {category}:{prog_name}"))?;
    }

    let mut ring_buf = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .context("EVENTS map not found in eBPF object")?,
    )?;
    let mut net_ring_buf = RingBuf::try_from(
        ebpf.take_map("NET_EVENTS")
            .context("NET_EVENTS map not found in eBPF object")?,
    )?;
    let mut file_ring_buf = RingBuf::try_from(
        ebpf.take_map("FILE_EVENTS")
            .context("FILE_EVENTS map not found in eBPF object")?,
    )?;
    let mut mem_ring_buf = RingBuf::try_from(
        ebpf.take_map("MEM_EVENTS")
            .context("MEM_EVENTS map not found in eBPF object")?,
    )?;

    let stats: StatsMap = Rc::new(RefCell::new(HashMap::new()));
    // (pid, syscall_nr) -> enter timestamp, so a rapid-fire syscall from another
    // thread of the same target doesn't clobber this one's pending entry.
    let mut pending: HashMap<(u32, u64), u64> = HashMap::new();

    let stats_for_drain = stats.clone();
    let mut drain_syscalls = move || {
        while let Some(item) = ring_buf.next() {
            if item.len() != size_of::<SyscallEvent>() {
                continue;
            }
            // SAFETY: peekbeam-ebpf only ever writes `SyscallEvent`-sized records to
            // this ring buffer, and the kernel guarantees 8-byte aligned reservations,
            // matching `SyscallEvent`'s alignment.
            let event = unsafe { item.as_ptr().cast::<SyscallEvent>().read_unaligned() };
            match event.kind {
                EventKind::Enter => {
                    pending.insert((event.pid, event.syscall_nr), event.timestamp_ns);
                }
                EventKind::Exit => {
                    if let Some(start) = pending.remove(&(event.pid, event.syscall_nr)) {
                        let dur = event.timestamp_ns.saturating_sub(start);
                        let mut stats = stats_for_drain.borrow_mut();
                        let entry = stats.entry(event.syscall_nr).or_default();
                        entry.count += 1;
                        entry.total_ns += dur;
                    }
                }
            }
        }
    };

    let connections: ConnMap = Rc::new(RefCell::new(HashMap::new()));
    let connections_for_drain = connections.clone();
    let mut drain_net_events = move || {
        while let Some(item) = net_ring_buf.next() {
            if item.len() != size_of::<NetEvent>() {
                continue;
            }
            // SAFETY: peekbeam-ebpf only ever writes `NetEvent`-sized records to
            // this ring buffer, and the kernel guarantees 8-byte aligned reservations,
            // matching `NetEvent`'s alignment.
            let event = unsafe { item.as_ptr().cast::<NetEvent>().read_unaligned() };
            let key = ConnectionKey {
                family: event.family,
                sport: event.sport,
                dport: event.dport,
                saddr: event.saddr,
                daddr: event.daddr,
            };
            let mut connections = connections_for_drain.borrow_mut();
            match event.kind {
                NetEventKind::StateChange if event.state == TCP_CLOSE => {
                    connections.remove(&key);
                }
                NetEventKind::StateChange => {
                    connections.entry(key).or_default().state = event.state;
                }
                NetEventKind::Retransmit => {
                    let entry = connections.entry(key).or_default();
                    entry.state = event.state;
                    entry.retransmits += 1;
                }
            }
        }
    };

    let files: FilesMap = Rc::new(RefCell::new(HashMap::new()));
    let files_for_drain = files.clone();
    let mut drain_file_events = move || {
        while let Some(item) = file_ring_buf.next() {
            if item.len() != size_of::<FileEvent>() {
                continue;
            }
            // SAFETY: peekbeam-ebpf only ever writes `FileEvent`-sized records to
            // this ring buffer, and the kernel guarantees 8-byte aligned reservations,
            // matching `FileEvent`'s alignment.
            let event = unsafe { item.as_ptr().cast::<FileEvent>().read_unaligned() };
            let key = (event.pid, event.fd);
            let mut files = files_for_drain.borrow_mut();
            match event.kind {
                FileEventKind::Open => {
                    files.insert(
                        key,
                        FileStats {
                            path: file_table::format_path(&event.path, event.path_len),
                            bytes_read: 0,
                            bytes_written: 0,
                            closed: false,
                        },
                    );
                }
                FileEventKind::Close => {
                    if let Some(entry) = files.get_mut(&key) {
                        entry.closed = true;
                    }
                }
                FileEventKind::Read => {
                    files.entry(key).or_insert_with(unknown_file).bytes_read += event.bytes as u64;
                }
                FileEventKind::Write => {
                    files.entry(key).or_insert_with(unknown_file).bytes_written += event.bytes as u64;
                }
            }
        }
    };

    let mem_events: MemEventStatsCell = Rc::new(RefCell::new(MemEventStats::default()));
    let mem_events_for_drain = mem_events.clone();
    let mut drain_mem_events = move || {
        while let Some(item) = mem_ring_buf.next() {
            if item.len() != size_of::<MemEvent>() {
                continue;
            }
            // SAFETY: peekbeam-ebpf only ever writes `MemEvent`-sized records to
            // this ring buffer, and the kernel guarantees 8-byte aligned reservations,
            // matching `MemEvent`'s alignment.
            let event = unsafe { item.as_ptr().cast::<MemEvent>().read_unaligned() };
            let mut stats = mem_events_for_drain.borrow_mut();
            match event.kind {
                MemEventKind::Alloc => {
                    stats.alloc_count += 1;
                    stats.alloc_bytes += event.bytes;
                }
                MemEventKind::Free => stats.free_count += 1,
            }
        }
    };

    let poll_events = move || {
        drain_syscalls();
        drain_net_events();
        drain_file_events();
        drain_mem_events();
    };

    let label = target.label();
    let memory_target = target.memory_target();
    let refresh = Duration::from_millis(args.refresh_ms);

    if args.json || args.duration.is_some() {
        let shutdown = signals::install()?;
        headless::run(
            label,
            memory_target,
            args.duration.map(Duration::from_secs),
            args.json,
            refresh,
            stats,
            connections,
            files,
            mem_events,
            poll_events,
            shutdown,
        )
    } else {
        tui::run(label, memory_target, refresh, stats, connections, files, mem_events, poll_events)
    }
}

/// A read/write landed on an fd we never saw opened (e.g. inherited from
/// before peekbeam started tracing) — still worth showing the byte volume.
fn unknown_file() -> FileStats {
    FileStats {
        path: "<unknown, opened before trace started>".to_string(),
        bytes_read: 0,
        bytes_written: 0,
        closed: false,
    }
}
