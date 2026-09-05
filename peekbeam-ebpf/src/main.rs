#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext as _,
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};
use peekbeam_common::{EventKind, SyscallEvent};

/// Holds exactly one entry: the target PID (FR1.1). Filtering happens here, in-kernel,
/// rather than in userspace, per the readme's filtering strategy (readme.md §5).
#[map]
static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Offset of the `id` (syscall number) field, common to both `raw_syscalls:sys_enter`
/// and `raw_syscalls:sys_exit` tracepoint formats, right after the 8-byte common header
/// (`common_type`, `common_flags`, `common_preempt_count`, `common_pid`).
const SYSCALL_NR_OFFSET: usize = 8;

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
    if unsafe { PID_FILTER.get(&pid) }.is_none() {
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
