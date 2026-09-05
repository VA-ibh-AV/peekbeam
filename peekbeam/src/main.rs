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
use clap::Parser;
use log::debug;
use peekbeam_common::{EventKind, SyscallEvent};

mod syscall_table;
mod tui;

/// Live, low-overhead syscall visibility for a single PID (Phase 1).
#[derive(Parser)]
#[command(name = "peekbeam", version, about)]
struct Args {
    /// PID to trace.
    #[arg(long)]
    pid: u32,

    /// TUI refresh interval, in milliseconds.
    #[arg(long, default_value_t = 1000)]
    refresh_ms: u64,
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

    check_privileges()?;
    check_target_exists(args.pid)?;
    raise_memlock_rlimit();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/peekbeam"
    )))
    .context("loading eBPF bytecode")?;

    let mut pid_filter: BpfHashMap<_, u32, u8> = BpfHashMap::try_from(
        ebpf.map_mut("PID_FILTER")
            .context("PID_FILTER map not found in eBPF object")?,
    )?;
    pid_filter.insert(args.pid, 1u8, 0)?;

    for prog_name in ["sys_enter", "sys_exit"] {
        let program: &mut TracePoint = ebpf
            .program_mut(prog_name)
            .with_context(|| format!("program `{prog_name}` not found in eBPF object"))?
            .try_into()?;
        program.load()?;
        program
            .attach("raw_syscalls", prog_name)
            .with_context(|| format!("attaching raw_syscalls:{prog_name}"))?;
    }

    let mut ring_buf = RingBuf::try_from(
        ebpf.map_mut("EVENTS")
            .context("EVENTS map not found in eBPF object")?,
    )?;

    let stats: StatsMap = Rc::new(RefCell::new(HashMap::new()));
    // (pid, syscall_nr) -> enter timestamp, so a rapid-fire syscall from another
    // thread of the same target doesn't clobber this one's pending entry.
    let mut pending: HashMap<(u32, u64), u64> = HashMap::new();

    let stats_for_drain = stats.clone();
    let drain_events = move || {
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

    tui::run(args.pid, Duration::from_millis(args.refresh_ms), stats, drain_events)
}
