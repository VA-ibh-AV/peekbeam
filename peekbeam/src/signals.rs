//! FR8.3: detach/exit cleanly on SIGINT/SIGTERM, not just the TUI's own
//! Ctrl+C key handling (which only works in raw mode, i.e. the interactive
//! TUI's own event loop). A plain `kill <pid>` or `docker stop`-style SIGTERM
//! would otherwise skip our cleanup entirely.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use anyhow::Context;
use signal_hook::consts::{SIGINT, SIGTERM};

pub fn install() -> anyhow::Result<Arc<AtomicBool>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, shutdown.clone()).context("registering SIGINT handler")?;
    signal_hook::flag::register(SIGTERM, shutdown.clone())
        .context("registering SIGTERM handler")?;
    Ok(shutdown)
}

pub fn requested(flag: &AtomicBool) -> bool {
    flag.load(Ordering::Relaxed)
}
