//! TCP state name + one-line annotation, and address formatting, for the
//! Network panel (FR3.3). Mirrors `syscall_table.rs`'s plain-language framing.

use std::net::{Ipv4Addr, Ipv6Addr};

use peekbeam_common::AF_INET6;

pub fn state_name(state: u16) -> &'static str {
    match state {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        12 => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

pub fn state_annotation(state: u16) -> &'static str {
    match state {
        1 => "connection open, actively usable",
        2 => "we sent SYN, waiting for the peer's reply",
        3 => "inbound SYN received, handshake in progress",
        4 | 5 => "we closed our side, waiting on the peer to close theirs",
        6 => "closed, waiting to make sure the peer saw it",
        7 => "connection fully closed",
        8 => "peer closed, waiting for us to close our side",
        9 => "we sent our final ack, waiting for it to land",
        10 => "listening for incoming connections",
        11 => "both sides closing simultaneously",
        12 => "inbound SYN queued, not yet accepted",
        _ => "unrecognized TCP state",
    }
}

pub fn format_addr(family: u16, addr: &[u8; 16]) -> String {
    if family == AF_INET6 {
        Ipv6Addr::from(*addr).to_string()
    } else {
        Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string()
    }
}
