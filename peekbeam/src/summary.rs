//! FR7.2/FR7.3: a point-in-time snapshot of everything peekbeam has seen,
//! rendered as JSON (`--json`, for piping/logging) or plain text (`--duration`
//! without `--json`, for a human reading CI output).

use std::collections::HashMap;

use serde::Serialize;

use crate::{ConnectionKey, ConnectionStats, FileStats, MemEventStats, SyscallStats, mem_stats, net_table, syscall_table};

#[derive(Serialize)]
pub struct Summary {
    pub target: String,
    pub uptime_secs: u64,
    pub syscalls: Vec<SyscallSummary>,
    pub connections: Vec<ConnectionSummary>,
    pub files: Vec<FileSummary>,
    pub kernel_allocs: u64,
    pub kernel_alloc_bytes: u64,
    pub kernel_frees: u64,
    pub memory: Option<MemorySummary>,
    pub page_faults: Option<FaultSummary>,
}

#[derive(Serialize)]
pub struct SyscallSummary {
    pub name: String,
    pub category: String,
    pub count: u64,
    pub total_us: f64,
    pub avg_us: f64,
}

#[derive(Serialize)]
pub struct ConnectionSummary {
    pub local: String,
    pub remote: String,
    pub state: String,
    pub retransmits: u64,
}

#[derive(Serialize)]
pub struct FileSummary {
    pub path: String,
    pub pid: u32,
    pub fd: i32,
    pub status: &'static str,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

#[derive(Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum MemorySummary {
    Cgroup {
        current_bytes: u64,
        anon_bytes: u64,
        file_bytes: u64,
        active_anon_bytes: u64,
        inactive_anon_bytes: u64,
    },
    Proc {
        rss_bytes: u64,
        anon_bytes: u64,
        file_bytes: u64,
        shmem_bytes: u64,
        num_processes: usize,
    },
}

#[derive(Serialize)]
pub struct FaultSummary {
    pub minor: u64,
    pub major: u64,
}

impl Summary {
    pub fn build(
        target: &str,
        uptime_secs: u64,
        stats: &HashMap<u64, SyscallStats>,
        connections: &HashMap<ConnectionKey, ConnectionStats>,
        files: &HashMap<(u32, i32), FileStats>,
        mem_events: MemEventStats,
        memory_target: &mem_stats::MemoryTarget,
    ) -> Self {
        let mut syscalls: Vec<SyscallSummary> = stats
            .iter()
            .map(|(&nr, &s)| {
                let info = syscall_table::lookup(nr);
                SyscallSummary {
                    name: info.name.to_string(),
                    category: info.category.to_string(),
                    count: s.count,
                    total_us: s.total_ns as f64 / 1000.0,
                    avg_us: s.avg_ns() as f64 / 1000.0,
                }
            })
            .collect();
        syscalls.sort_by(|a, b| b.total_us.partial_cmp(&a.total_us).unwrap_or(std::cmp::Ordering::Equal));

        let mut conns: Vec<ConnectionSummary> = connections
            .iter()
            .map(|(k, s)| ConnectionSummary {
                local: format!("{}:{}", net_table::format_addr(k.family, &k.saddr), k.sport),
                remote: format!("{}:{}", net_table::format_addr(k.family, &k.daddr), k.dport),
                state: net_table::state_name(s.state).to_string(),
                retransmits: s.retransmits,
            })
            .collect();
        conns.sort_by(|a, b| b.retransmits.cmp(&a.retransmits));

        let mut file_list: Vec<FileSummary> = files
            .iter()
            .map(|(&(pid, fd), s)| FileSummary {
                path: s.path.clone(),
                pid,
                fd,
                status: if s.closed { "closed" } else { "open" },
                bytes_read: s.bytes_read,
                bytes_written: s.bytes_written,
            })
            .collect();
        file_list.sort_by(|a, b| (b.bytes_read + b.bytes_written).cmp(&(a.bytes_read + a.bytes_written)));

        let memory = mem_stats::read(memory_target).ok().map(|r| match r {
            mem_stats::MemReport::Cgroup {
                current_bytes,
                anon_bytes,
                file_bytes,
                active_anon_bytes,
                inactive_anon_bytes,
            } => MemorySummary::Cgroup {
                current_bytes,
                anon_bytes,
                file_bytes,
                active_anon_bytes,
                inactive_anon_bytes,
            },
            mem_stats::MemReport::Process {
                rss_bytes,
                anon_bytes,
                file_bytes,
                shmem_bytes,
                num_processes,
            } => MemorySummary::Proc {
                rss_bytes,
                anon_bytes,
                file_bytes,
                shmem_bytes,
                num_processes,
            },
        });
        let page_faults = mem_stats::read_faults(memory_target)
            .ok()
            .map(|f| FaultSummary { minor: f.min_flt, major: f.maj_flt });

        Self {
            target: target.to_string(),
            uptime_secs,
            syscalls,
            connections: conns,
            files: file_list,
            kernel_allocs: mem_events.alloc_count,
            kernel_alloc_bytes: mem_events.alloc_bytes,
            kernel_frees: mem_events.free_count,
            memory,
            page_faults,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_plain_text(&self) -> String {
        use std::fmt::Write as _;

        let mut out = String::new();
        let _ = writeln!(out, "peekbeam summary — {}  (uptime {}s)", self.target, self.uptime_secs);

        let _ = writeln!(out, "\nSyscalls:");
        for s in &self.syscalls {
            let _ = writeln!(
                out,
                "  {:<20} count={:<8} total={:.2}us avg={:.2}us  [{}]",
                s.name, s.count, s.total_us, s.avg_us, s.category
            );
        }

        if !self.connections.is_empty() {
            let _ = writeln!(out, "\nConnections:");
            for c in &self.connections {
                let _ = writeln!(out, "  {} -> {}  state={}  retransmits={}", c.local, c.remote, c.state, c.retransmits);
            }
        }

        if !self.files.is_empty() {
            let _ = writeln!(out, "\nFiles:");
            for f in &self.files {
                let _ = writeln!(
                    out,
                    "  {} (pid={},fd={})  {}  read={} written={}",
                    f.path, f.pid, f.fd, f.status, f.bytes_read, f.bytes_written
                );
            }
        }

        let _ = writeln!(
            out,
            "\nKernel allocs: {} ({})\nKernel frees: {}",
            self.kernel_allocs,
            mem_stats::format_bytes(self.kernel_alloc_bytes),
            self.kernel_frees
        );

        match &self.memory {
            Some(MemorySummary::Cgroup { current_bytes, .. }) => {
                let _ = writeln!(out, "Memory (cgroup): {}", mem_stats::format_bytes(*current_bytes));
            }
            Some(MemorySummary::Proc { rss_bytes, num_processes, .. }) => {
                let _ = writeln!(
                    out,
                    "Memory (proc): {} RSS across {num_processes} process(es)",
                    mem_stats::format_bytes(*rss_bytes)
                );
            }
            None => {
                let _ = writeln!(out, "Memory: unavailable");
            }
        }

        if let Some(f) = &self.page_faults {
            let _ = writeln!(out, "Page faults: minor={} major={}", f.minor, f.major);
        }

        out
    }
}
