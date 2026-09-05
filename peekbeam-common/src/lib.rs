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

/// Network event layout (FR3), read from the `sock:inet_sock_set_state` and
/// `tcp:tcp_retransmit_skb` tracepoint formats. `state`/`family` use the kernel's
/// own numeric constants (`TCP_ESTABLISHED` = 1, ..., `TCP_CLOSE` = 7; `AF_INET`
/// = 2, `AF_INET6` = 10) so `peekbeam-ebpf` doesn't need to duplicate naming
/// tables that already live in `peekbeam`'s userspace side.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NetEvent {
    pub kind: NetEventKind,
    pub family: u16,
    pub state: u16,
    pub sport: u16,
    pub dport: u16,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub timestamp_ns: u64,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetEventKind {
    /// Any TCP state transition, from `sock:inet_sock_set_state` (FR3.1). A
    /// transition to `state == TCP_CLOSE` (7) marks the connection's end.
    StateChange = 0,
    /// From `tcp:tcp_retransmit_skb` (FR3.2).
    Retransmit = 1,
}

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const TCP_CLOSE: u16 = 7;
