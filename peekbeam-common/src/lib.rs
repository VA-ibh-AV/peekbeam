#![no_std]

/// Shared ring buffer event layout for `peekbeam-ebpf` (producer) and `peekbeam` (consumer).
///
/// `align_of::<SyscallEvent>()` must stay <= 8: the kernel ring buffer only guarantees
/// 8-byte aligned reservations (see `RingBuf::reserve`/`RingBuf::output` in `aya-ebpf`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SyscallEvent {
    pub pid: u32,
    pub kind: EventKind,
    pub _pad: [u8; 3],
    pub syscall_nr: u64,
    pub timestamp_ns: u64,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Enter = 0,
    Exit = 1,
}
