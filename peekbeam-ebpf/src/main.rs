#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext as _,
    helpers::{bpf_get_current_cgroup_id, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};
use peekbeam_common::{
    AF_INET6, EventKind, FILE_PATH_MAX, FileEvent, FileEventKind, MemEvent, MemEventKind, NetEvent,
    NetEventKind, SyscallEvent, TCP_CLOSE,
};

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

/// Pending `openat`/`openat2` pathname, stashed at `sys_enter` and consumed at
/// `sys_exit` once the resulting fd is known (FR4.1). Keyed by pid (tgid): a
/// single thread can't be inside two syscalls at once, so this is safe under
/// the same "one pending op per tgid" simplification already used for syscall
/// latency tracking (`peekbeam`'s userspace `pending` map).
#[map]
static PENDING_OPEN_PATH: HashMap<u32, PendingOpen> = HashMap::with_max_entries(128, 0);

/// Pending fd for `read`/`write`/`pread64`/`pwrite64`/`close`, stashed at
/// `sys_enter` (where the fd argument lives) and consumed at `sys_exit` (where
/// the byte count / success result lives) (FR4.2).
#[map]
static PENDING_FD: HashMap<u32, i32> = HashMap::with_max_entries(128, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingOpen {
    path: [u8; FILE_PATH_MAX],
    path_len: u16,
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static NET_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static MEM_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Offset of the `id` (syscall number) field, common to both `raw_syscalls:sys_enter`
/// and `raw_syscalls:sys_exit` tracepoint formats, right after the 8-byte common header
/// (`common_type`, `common_flags`, `common_preempt_count`, `common_pid`).
const SYSCALL_NR_OFFSET: usize = 8;

// aarch64 syscall numbers (see `syscalls` crate / `syscalls::Sysno`), for the
// handful of syscalls FR4 cares about. `sys_enter`'s `args[N]` sit at
// offset 16 + N*8; `sys_exit`'s `ret` sits at offset 16.
const SYS_OPENAT: i64 = 56;
const SYS_CLOSE: i64 = 57;
const SYS_READ: i64 = 63;
const SYS_WRITE: i64 = 64;
const SYS_PREAD64: i64 = 67;
const SYS_PWRITE64: i64 = 68;
const SYS_OPENAT2: i64 = 437;

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

    // Best-effort: a failed user-string/arg read here shouldn't take down
    // syscall counting above, so errors are swallowed rather than propagated.
    handle_file_syscall(ctx, kind, pid, syscall_nr);

    Ok(0)
}

/// FR4: file access visibility, built from the syscalls we're already
/// tracing (no new hook points, no kernel struct access, so no BTF/CO-RE
/// dependency).
fn handle_file_syscall(ctx: &TracePointContext, kind: EventKind, pid: u32, nr: i64) {
    let _ = match (kind, nr) {
        (EventKind::Enter, SYS_OPENAT | SYS_OPENAT2) => stash_open_path(ctx, pid),
        (EventKind::Exit, SYS_OPENAT | SYS_OPENAT2) => emit_open_result(ctx, pid),
        (EventKind::Enter, SYS_READ | SYS_WRITE | SYS_PREAD64 | SYS_PWRITE64 | SYS_CLOSE) => {
            stash_fd(ctx, pid)
        }
        (EventKind::Exit, SYS_READ | SYS_PREAD64) => emit_read_write(ctx, pid, FileEventKind::Read),
        (EventKind::Exit, SYS_WRITE | SYS_PWRITE64) => {
            emit_read_write(ctx, pid, FileEventKind::Write)
        }
        (EventKind::Exit, SYS_CLOSE) => emit_close(ctx, pid),
        _ => Ok(()),
    };
}

/// `sys_enter`'s `args[1]` (offset 16 + 1*8 = 24) is `openat`/`openat2`'s
/// `filename` argument, a userspace `const char *`.
fn stash_open_path(ctx: &TracePointContext, pid: u32) -> Result<(), i32> {
    let filename_ptr: u64 = unsafe { ctx.read_at(24) }?;
    let mut path = [0u8; FILE_PATH_MAX];
    let path_len = unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut path) }?.len() as u16;
    PENDING_OPEN_PATH.insert(&pid, &PendingOpen { path, path_len }, 0)
}

fn emit_open_result(ctx: &TracePointContext, pid: u32) -> Result<(), i32> {
    let pending = unsafe { PENDING_OPEN_PATH.get(&pid) }.copied();
    let _ = PENDING_OPEN_PATH.remove(&pid);
    let Some(pending) = pending else {
        return Ok(());
    };

    let ret: i64 = unsafe { ctx.read_at(16) }?;
    if ret < 0 {
        return Ok(()); // openat failed; nothing to report
    }

    let event = FileEvent {
        pid,
        kind: FileEventKind::Open,
        fd: ret as i32,
        bytes: 0,
        path_len: pending.path_len,
        path: pending.path,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };
    FILE_EVENTS.output::<FileEvent>(&event, 0)
}

/// `sys_enter`'s `args[0]` (offset 16) is every one of these syscalls' `fd`
/// argument.
fn stash_fd(ctx: &TracePointContext, pid: u32) -> Result<(), i32> {
    let fd: i64 = unsafe { ctx.read_at(16) }?;
    PENDING_FD.insert(&pid, &(fd as i32), 0)
}

fn emit_read_write(ctx: &TracePointContext, pid: u32, kind: FileEventKind) -> Result<(), i32> {
    let Some(fd) = unsafe { PENDING_FD.get(&pid) }.copied() else {
        return Ok(());
    };
    let _ = PENDING_FD.remove(&pid);

    let bytes: i64 = unsafe { ctx.read_at(16) }?;
    if bytes < 0 {
        return Ok(()); // read/write failed
    }

    let event = FileEvent {
        pid,
        kind,
        fd,
        bytes,
        path_len: 0,
        path: [0; FILE_PATH_MAX],
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };
    FILE_EVENTS.output::<FileEvent>(&event, 0)
}

fn emit_close(ctx: &TracePointContext, pid: u32) -> Result<(), i32> {
    let Some(fd) = unsafe { PENDING_FD.get(&pid) }.copied() else {
        return Ok(());
    };
    let _ = PENDING_FD.remove(&pid);

    let ret: i64 = unsafe { ctx.read_at(16) }?;
    if ret != 0 {
        return Ok(()); // close failed
    }

    let event = FileEvent {
        pid,
        kind: FileEventKind::Close,
        fd,
        bytes: 0,
        path_len: 0,
        path: [0; FILE_PATH_MAX],
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };
    FILE_EVENTS.output::<FileEvent>(&event, 0)
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

/// `kmem:kmalloc` tracepoint format (this host, kernel 6.12):
/// call_site@8(8) ptr@16(8) bytes_req@24(8) bytes_alloc@32(8) gfp_flags@40(8) node@48(4).
#[tracepoint]
pub fn kmalloc(ctx: TracePointContext) -> u32 {
    match try_kmalloc(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kmalloc(ctx: &TracePointContext) -> Result<u32, u32> {
    let pid = ctx.tgid();
    if !matches_target(pid) {
        return Ok(0);
    }

    let bytes: u64 = unsafe { ctx.read_at(32) }.map_err(|_| 1u32)?;
    let event = MemEvent {
        pid,
        kind: MemEventKind::Alloc,
        bytes,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };
    MEM_EVENTS.output::<MemEvent>(&event, 0).map_err(|_| 1u32)?;
    Ok(0)
}

/// `kmem:kfree` tracepoint format (this host, kernel 6.12): call_site@8(8) ptr@16(8).
/// No size field — `kfree` doesn't carry it in the trace event; the free count
/// alone (paired against `kmalloc`'s allocation rate) is still useful signal.
#[tracepoint]
pub fn kfree(ctx: TracePointContext) -> u32 {
    match try_kfree(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kfree(ctx: &TracePointContext) -> Result<u32, u32> {
    let pid = ctx.tgid();
    if !matches_target(pid) {
        return Ok(0);
    }

    let event = MemEvent {
        pid,
        kind: MemEventKind::Free,
        bytes: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };
    MEM_EVENTS.output::<MemEvent>(&event, 0).map_err(|_| 1u32)?;
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
