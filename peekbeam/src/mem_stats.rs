//! FR5.3: cgroup memory controller stats, read directly from cgroupfs on the
//! TUI's own refresh interval — a lighter-weight complement to raw tracepoint
//! data (FR5.1/5.2, not implemented: this host has no kernel BTF, so a CO-RE
//! page-fault/alloc read isn't available here; see readme.md §7).

use std::fs;

use anyhow::Context;

use crate::container::CGROUP_ROOT;

#[derive(Clone, Copy, Default)]
pub struct MemStats {
    pub current_bytes: u64,
    pub anon_bytes: u64,
    pub file_bytes: u64,
    pub active_anon_bytes: u64,
    pub inactive_anon_bytes: u64,
}

pub fn read(cgroup_path: &str) -> anyhow::Result<MemStats> {
    let base = format!("{CGROUP_ROOT}{cgroup_path}");

    let current_bytes = fs::read_to_string(format!("{base}/memory.current"))
        .with_context(|| format!("reading {base}/memory.current"))?
        .trim()
        .parse()
        .context("parsing memory.current")?;

    let stat = fs::read_to_string(format!("{base}/memory.stat"))
        .with_context(|| format!("reading {base}/memory.stat"))?;

    let mut stats = MemStats {
        current_bytes,
        ..Default::default()
    };
    for line in stat.lines() {
        let mut parts = line.split_whitespace();
        let (Some(key), Some(val)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(val) = val.parse::<u64>() else {
            continue;
        };
        match key {
            "anon" => stats.anon_bytes = val,
            "file" => stats.file_bytes = val,
            "active_anon" => stats.active_anon_bytes = val,
            "inactive_anon" => stats.inactive_anon_bytes = val,
            _ => {}
        }
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
