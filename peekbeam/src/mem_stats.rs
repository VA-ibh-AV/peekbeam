//! FR5.3: memory visibility, read on the TUI's own refresh interval rather
//! than via raw tracepoints (FR5.1/5.2, not implemented — this host has no
//! kernel BTF, so a CO-RE page-fault/alloc read isn't available; see
//! readme.md §7).
//!
//! Prefers cgroup memory controller stats (`memory.current`/`memory.stat`)
//! per FR5.3's own wording, but that controller isn't always delegated (this
//! project's own rootless-Docker dev host only delegates cpuset/cpu/io/pids,
//! confirmed by checking `cgroup.controllers`). Falls back to summing
//! `/proc/<pid>/status` over the target's processes, which needs no cgroup
//! delegation at all — `cgroup.procs` itself is always present regardless of
//! which controllers are delegated.

use std::fs;

use anyhow::{Context, anyhow};

use crate::container::CGROUP_ROOT;

pub enum MemoryTarget {
    /// Path under `CGROUP_ROOT`, e.g. `/system.slice/docker-<id>.scope`.
    Cgroup(String),
    Pid(u32),
}

pub enum MemReport {
    Cgroup {
        current_bytes: u64,
        anon_bytes: u64,
        file_bytes: u64,
        active_anon_bytes: u64,
        inactive_anon_bytes: u64,
    },
    Process {
        rss_bytes: u64,
        anon_bytes: u64,
        file_bytes: u64,
        shmem_bytes: u64,
        num_processes: usize,
    },
}

pub fn read(target: &MemoryTarget) -> anyhow::Result<MemReport> {
    match target {
        MemoryTarget::Pid(pid) => read_processes(&[*pid]),
        MemoryTarget::Cgroup(path) => read_cgroup(path).or_else(|_| {
            let pids = read_cgroup_procs(path)?;
            read_processes(&pids)
        }),
    }
}

fn read_cgroup(cgroup_path: &str) -> anyhow::Result<MemReport> {
    let base = format!("{CGROUP_ROOT}{cgroup_path}");

    let current_bytes = fs::read_to_string(format!("{base}/memory.current"))
        .with_context(|| format!("reading {base}/memory.current"))?
        .trim()
        .parse()
        .context("parsing memory.current")?;

    let stat = fs::read_to_string(format!("{base}/memory.stat"))
        .with_context(|| format!("reading {base}/memory.stat"))?;

    let (mut anon_bytes, mut file_bytes, mut active_anon_bytes, mut inactive_anon_bytes) = (0, 0, 0, 0);
    for line in stat.lines() {
        let mut parts = line.split_whitespace();
        let (Some(key), Some(val)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(val) = val.parse::<u64>() else {
            continue;
        };
        match key {
            "anon" => anon_bytes = val,
            "file" => file_bytes = val,
            "active_anon" => active_anon_bytes = val,
            "inactive_anon" => inactive_anon_bytes = val,
            _ => {}
        }
    }

    Ok(MemReport::Cgroup {
        current_bytes,
        anon_bytes,
        file_bytes,
        active_anon_bytes,
        inactive_anon_bytes,
    })
}

/// `cgroup.procs` lists the PIDs in a cgroup and is always present, unlike
/// `memory.*`, which only exists when the memory controller is delegated.
fn read_cgroup_procs(cgroup_path: &str) -> anyhow::Result<Vec<u32>> {
    let path = format!("{CGROUP_ROOT}{cgroup_path}/cgroup.procs");
    let contents = fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    Ok(contents.lines().filter_map(|l| l.trim().parse().ok()).collect())
}

fn read_processes(pids: &[u32]) -> anyhow::Result<MemReport> {
    let (mut rss_bytes, mut anon_bytes, mut file_bytes, mut shmem_bytes) = (0, 0, 0, 0);
    let mut num_processes = 0;

    for &pid in pids {
        let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue; // process may have exited since cgroup.procs/target was read
        };
        num_processes += 1;
        for line in status.lines() {
            let mut parts = line.split_whitespace();
            let (Some(key), Some(val)) = (parts.next(), parts.next()) else {
                continue;
            };
            let Ok(kb) = val.parse::<u64>() else {
                continue;
            };
            match key {
                "VmRSS:" => rss_bytes += kb * 1024,
                "RssAnon:" => anon_bytes += kb * 1024,
                "RssFile:" => file_bytes += kb * 1024,
                "RssShmem:" => shmem_bytes += kb * 1024,
                _ => {}
            }
        }
    }

    if num_processes == 0 {
        return Err(anyhow!("no live processes found (target may have exited)"));
    }

    Ok(MemReport::Process {
        rss_bytes,
        anon_bytes,
        file_bytes,
        shmem_bytes,
        num_processes,
    })
}

/// FR5.2: minor/major page fault counts, since each process started (not since
/// peekbeam attached) — read from `/proc/<pid>/stat` fields 10/12 (`minflt`/
/// `majflt`), summed like the `/proc`-based memory fallback. No raw
/// `exceptions:page_fault_user`-style tracepoint exists on this arm64 kernel
/// (that category is x86-specific; confirmed absent here), but this needs no
/// tracepoint or BTF at all.
#[derive(Clone, Copy, Default)]
pub struct FaultStats {
    pub min_flt: u64,
    pub maj_flt: u64,
}

pub fn read_faults(target: &MemoryTarget) -> anyhow::Result<FaultStats> {
    let pids = match target {
        MemoryTarget::Pid(pid) => vec![*pid],
        MemoryTarget::Cgroup(path) => read_cgroup_procs(path)?,
    };

    let mut stats = FaultStats::default();
    let mut found_any = false;
    for pid in pids {
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        // Fields after `pid (comm) state ...` are space-separated, but `comm`
        // itself may contain spaces/parens, so split after the last ')'.
        let Some(after_comm) = stat.rfind(')').map(|i| &stat[i + 1..]) else {
            continue;
        };
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        // `state` is field 3 in the full record and is `fields[0]` here, so
        // `minflt` (field 10) is `fields[7]`, `majflt` (field 12) is `fields[9]`.
        let (Some(min_flt), Some(maj_flt)) = (fields.get(7), fields.get(9)) else {
            continue;
        };
        stats.min_flt += min_flt.parse().unwrap_or(0);
        stats.maj_flt += maj_flt.parse().unwrap_or(0);
        found_any = true;
    }

    if !found_any {
        return Err(anyhow!("no live processes found (target may have exited)"));
    }
    Ok(stats)
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
