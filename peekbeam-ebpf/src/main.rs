#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext as _,
    helpers::{bpf_get_current_cgroup_id, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};
use peekbeam_common::{AF_INET6, EventKind, NetEvent, NetEventKind, SyscallEvent, TCP_CLOSE};

/// Holds exactly one entry: the target PID, for `--pid` mode (FR1.1). Filtering
/// happens here, in-kernel, rather than in userspace (readme.md §5).
#[map]
static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

/// Holds exactly one entry: the target container's cgroup id, for `--container`
/// mode (FR1.2). A process matches if it's in this cgroup, covering every process
/// in the container (init, workers, ...), not just a single PID.
#[map]
static CGROUP_FILTER: HashMap<u64, u8> = HashMap::with_max_entries(1, 0);

/// Sockets already confirmed to belong to the target, keyed by the kernel's
/// `struct sock *` address (FR3). Needed because most TCP state transitions and
/// all retransmits fire in softirq context, not the owning process's context, so
/// `matches_target` (current pid/cgroup) can't be checked directly there. We
/// learn that a socket belongs to the target the first time we see it change
/// state *while* in the target's own context, then match by pointer identity
/// for every event after that.
#[map]
static TRACKED_SOCKS: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static NET_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Offset of the `id` (syscall number) field, common to both `raw_syscalls:sys_enter`
/// and `raw_syscalls:sys_exit` tracepoint formats, right after the 8-byte common header
/// (`common_type`, `common_flags`, `common_preempt_count`, `common_pid`).
const SYSCALL_NR_OFFSET: usize = 8;

#[inline(always)]
fn matches_target(pid: u32) -> bool {
    if unsafe { PID_FILTER.get(&pid) }.is_some() {
        return true;
    }
    // Only bother resolving the (costlier) cgroup id if we're actually in
    // --container mode, i.e. CGROUP_FILTER has an entry.
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    unsafe { CGROUP_FILTER.get(&cgroup_id) }.is_some()
}

#[tracepoint]
pub fn sys_enter(ctx: TracePointContext) -> u32 {
    match try_emit(&ctx, EventKind::Enter) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn sys_exit(ctx: TracePointContext) -> u32 {
    match try_emit(&ctx, EventKind::Exit) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_emit(ctx: &TracePointContext, kind: EventKind) -> Result<u32, u32> {
    let pid = ctx.tgid();
    if !matches_target(pid) {
        return Ok(0);
    }

    let syscall_nr: i64 = unsafe { ctx.read_at(SYSCALL_NR_OFFSET) }.map_err(|_| 1u32)?;

    let event = SyscallEvent {
        pid,
        kind,
        _pad: [0; 3],
        syscall_nr: syscall_nr as u64,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };

    EVENTS.output::<SyscallEvent>(&event, 0).map_err(|_| 1u32)?;
    Ok(0)
}

/// `sock:inet_sock_set_state` tracepoint format (this host, kernel 6.12):
/// skaddr@8(8) oldstate@16(4) newstate@20(4) sport@24(2) dport@26(2) family@28(2)
/// protocol@30(2) saddr@32(4) daddr@36(4) saddr_v6@40(16) daddr_v6@56(16).
#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_net_state(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_net_state(ctx: &TracePointContext) -> Result<u32, u32> {
    let skaddr: u64 = unsafe { ctx.read_at(8) }.map_err(|_| 1u32)?;
    let already_tracked = unsafe { TRACKED_SOCKS.get(&skaddr) }.is_some();

    if !already_tracked && !matches_target(ctx.tgid()) {
        return Ok(0);
    }
    if !already_tracked {
        let _ = TRACKED_SOCKS.insert(&skaddr, &1u8, 0);
    }

    let newstate: i32 = unsafe { ctx.read_at(20) }.map_err(|_| 1u32)?;
    let sport: u16 = unsafe { ctx.read_at(24) }.map_err(|_| 1u32)?;
    let dport: u16 = unsafe { ctx.read_at(26) }.map_err(|_| 1u32)?;
    let family: u16 = unsafe { ctx.read_at(28) }.map_err(|_| 1u32)?;
    let state = newstate as u16;

    let mut saddr = [0u8; 16];
    let mut daddr = [0u8; 16];
    if family == AF_INET6 {
        saddr = unsafe { ctx.read_at(40) }.map_err(|_| 1u32)?;
        daddr = unsafe { ctx.read_at(56) }.map_err(|_| 1u32)?;
    } else {
        let s4: [u8; 4] = unsafe { ctx.read_at(32) }.map_err(|_| 1u32)?;
        let d4: [u8; 4] = unsafe { ctx.read_at(36) }.map_err(|_| 1u32)?;
        saddr[..4].copy_from_slice(&s4);
        daddr[..4].copy_from_slice(&d4);
    }

    let event = NetEvent {
        kind: NetEventKind::StateChange,
        family,
        state,
        sport,
        dport,
        saddr,
        daddr,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };
    NET_EVENTS.output::<NetEvent>(&event, 0).map_err(|_| 1u32)?;

    if state == TCP_CLOSE {
        let _ = TRACKED_SOCKS.remove(&skaddr);
    }

    Ok(0)
}

/// `tcp:tcp_retransmit_skb` tracepoint format (this host, kernel 6.12):
/// skbaddr@8(8) skaddr@16(8) state@24(4) sport@28(2) dport@30(2) family@32(2)
/// saddr@34(4) daddr@38(4) saddr_v6@42(16) daddr_v6@58(16).
#[tracepoint]
pub fn tcp_retransmit_skb(ctx: TracePointContext) -> u32 {
    match try_net_retransmit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_net_retransmit(ctx: &TracePointContext) -> Result<u32, u32> {
    let skaddr: u64 = unsafe { ctx.read_at(16) }.map_err(|_| 1u32)?;
    if unsafe { TRACKED_SOCKS.get(&skaddr) }.is_none() {
        return Ok(0);
    }

    let state: i32 = unsafe { ctx.read_at(24) }.map_err(|_| 1u32)?;
    let sport: u16 = unsafe { ctx.read_at(28) }.map_err(|_| 1u32)?;
    let dport: u16 = unsafe { ctx.read_at(30) }.map_err(|_| 1u32)?;
    let family: u16 = unsafe { ctx.read_at(32) }.map_err(|_| 1u32)?;

    let mut saddr = [0u8; 16];
    let mut daddr = [0u8; 16];
    if family == AF_INET6 {
        saddr = unsafe { ctx.read_at(42) }.map_err(|_| 1u32)?;
        daddr = unsafe { ctx.read_at(58) }.map_err(|_| 1u32)?;
    } else {
        let s4: [u8; 4] = unsafe { ctx.read_at(34) }.map_err(|_| 1u32)?;
        let d4: [u8; 4] = unsafe { ctx.read_at(38) }.map_err(|_| 1u32)?;
        saddr[..4].copy_from_slice(&s4);
        daddr[..4].copy_from_slice(&d4);
    }

    let event = NetEvent {
        kind: NetEventKind::Retransmit,
        family,
        state: state as u16,
        sport,
        dport,
        saddr,
        daddr,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };
    NET_EVENTS.output::<NetEvent>(&event, 0).map_err(|_| 1u32)?;
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
