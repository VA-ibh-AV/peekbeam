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
use peekbeam_common::{EventKind, NetEvent, NetEventKind, SyscallEvent, TCP_CLOSE};

mod container;
mod mem_stats;
mod net_table;
mod syscall_table;
mod tui;

/// Live, low-overhead syscall visibility for one target: a PID or a container.
#[derive(Parser)]
#[command(name = "peekbeam", version, about)]
#[command(group(ArgGroup::new("target").required(true).args(["pid", "container"])))]
struct Args {
    /// PID to trace.
    #[arg(long)]
    pid: Option<u32>,

    /// Container ID or name to trace (Docker only, cgroup v2 hosts only).
    #[arg(long)]
    container: Option<String>,

    /// TUI refresh interval, in milliseconds.
    #[arg(long, default_value_t = 1000)]
    refresh_ms: u64,
}

enum Target {
    Pid { pid: u32, cgroup_path: Option<String> },
    Container(container::ContainerTarget),
}

impl Target {
    fn label(&self) -> String {
        match self {
            Target::Pid { pid, .. } => format!("PID {pid}"),
            Target::Container(c) => {
                format!("container {} (cgroup {})", &c.full_id[..12.min(c.full_id.len())], c.cgroup_id)
            }
        }
    }

    /// Path under `container::CGROUP_ROOT`, if resolvable, for FR5.3 (memory
    /// panel). Always present for `--container`; for `--pid` it depends on
    /// whether that PID's own cgroup could be read.
    fn cgroup_path(&self) -> Option<&str> {
        match self {
            Target::Pid { cgroup_path, .. } => cgroup_path.as_deref(),
            Target::Container(c) => Some(&c.cgroup_path),
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
        let cgroup_path = container::cgroup_path_for_pid(pid).ok();
        Target::Pid { pid, cgroup_path }
    } else if let Some(container_id) = args.container.as_deref() {
        Target::Container(container::resolve(container_id)?)
    } else {
        unreachable!("clap requires exactly one of --pid/--container")
    };

    check_privileges()?;
    raise_memlock_rlimit();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/peekbeam"
    )))
    .context("loading eBPF bytecode")?;

    match &target {
        Target::Pid { pid, .. } => {
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
    }

    for (category, prog_name) in [
        ("raw_syscalls", "sys_enter"),
        ("raw_syscalls", "sys_exit"),
        ("sock", "inet_sock_set_state"),
        ("tcp", "tcp_retransmit_skb"),
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

    let poll_events = move || {
        drain_syscalls();
        drain_net_events();
    };

    let label = target.label();
    let cgroup_path = target.cgroup_path().map(str::to_string);

    tui::run(
        label,
        cgroup_path,
        Duration::from_millis(args.refresh_ms),
        stats,
        connections,
        poll_events,
    )
}
