//! FR7.3: `--duration` runs a fixed window then exits with one final summary,
//! for scripted/CI use. FR7.2: `--json` controls that summary's format, and
//! (used alone, without `--duration`) switches to a streaming mode — one
//! JSON line per refresh interval, for piping into another tool or a log
//! collector during an incident. Neither needs a terminal at all: this is a
//! plain poll loop, not the interactive TUI.

use std::{
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

use crate::{ConnMap, FilesMap, MemEventStatsCell, StatsMap, mem_stats, signals, summary::Summary};

#[allow(clippy::too_many_arguments)]
pub fn run(
    target: String,
    memory_target: mem_stats::MemoryTarget,
    duration: Option<Duration>,
    json: bool,
    refresh: Duration,
    stats: StatsMap,
    connections: ConnMap,
    files: FilesMap,
    mem_events: MemEventStatsCell,
    mut poll_events: impl FnMut(),
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let start = Instant::now();
    let mut last_emit = Instant::now();

    loop {
        poll_events();

        if signals::requested(&shutdown) {
            break;
        }
        if let Some(d) = duration {
            if start.elapsed() >= d {
                break;
            }
        } else if last_emit.elapsed() >= refresh {
            let summary = build_summary(&target, start, &stats, &connections, &files, &mem_events, &memory_target);
            println!("{}", summary.to_json());
            last_emit = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(50));
    }

    let summary = build_summary(&target, start, &stats, &connections, &files, &mem_events, &memory_target);
    if json {
        println!("{}", summary.to_json());
    } else {
        println!("{}", summary.to_plain_text());
    }

    Ok(())
}

fn build_summary(
    target: &str,
    start: Instant,
    stats: &StatsMap,
    connections: &ConnMap,
    files: &FilesMap,
    mem_events: &MemEventStatsCell,
    memory_target: &mem_stats::MemoryTarget,
) -> Summary {
    Summary::build(
        target,
        start.elapsed().as_secs(),
        &stats.borrow(),
        &connections.borrow(),
        &files.borrow(),
        *mem_events.borrow(),
        memory_target,
    )
}
