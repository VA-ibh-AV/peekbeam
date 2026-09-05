use std::{
    io::{self, Stdout},
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::{ConnMap, ConnectionKey, ConnectionStats, StatsMap, mem_stats, net_table, syscall_table};

#[derive(Clone, Copy, PartialEq)]
enum View {
    Syscalls,
    Network,
    Memory,
}

#[derive(Clone, Copy, PartialEq)]
enum SortBy {
    Count,
    Time,
}

/// FR6.1-6.3: live-updating Syscalls + Network panels (Tab switches between
/// them), sortable, with a summary header. `poll_events` is called once per
/// loop tick (~every 50ms) to drain both ring buffers and update `stats` /
/// `connections` before the next redraw, keeping eBPF specifics out of this
/// module. Restores the terminal on every exit path (including Ctrl+C/'q') so
/// no eBPF probes are left attached to a hung terminal session.
pub fn run(
    target: String,
    memory_target: mem_stats::MemoryTarget,
    refresh: Duration,
    stats: StatsMap,
    connections: ConnMap,
    mut poll_events: impl FnMut(),
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(
        &mut terminal,
        &target,
        &memory_target,
        refresh,
        stats,
        connections,
        &mut poll_events,
    );

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    target: &str,
    memory_target: &mem_stats::MemoryTarget,
    refresh: Duration,
    stats: StatsMap,
    connections: ConnMap,
    poll_events: &mut impl FnMut(),
) -> anyhow::Result<()> {
    let start = Instant::now();
    let mut view = View::Syscalls;
    let mut sort_by = SortBy::Time;
    let mut last_draw = Instant::now()
        .checked_sub(refresh)
        .unwrap_or_else(Instant::now);

    loop {
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                        KeyCode::Tab => {
                            view = match view {
                                View::Syscalls => View::Network,
                                View::Network => View::Memory,
                                View::Memory => View::Syscalls,
                            };
                        }
                        KeyCode::Char('s') if view == View::Syscalls => {
                            sort_by = match sort_by {
                                SortBy::Count => SortBy::Time,
                                SortBy::Time => SortBy::Count,
                            };
                        }
                        _ => {}
                    }
                }
            }
        }

        poll_events();

        if last_draw.elapsed() >= refresh {
            match view {
                View::Syscalls => {
                    let rows: Vec<(u64, crate::SyscallStats)> =
                        stats.borrow().iter().map(|(&nr, &s)| (nr, s)).collect();
                    draw_syscalls(terminal, target, start.elapsed(), sort_by, rows)?;
                }
                View::Network => {
                    let rows: Vec<(ConnectionKey, ConnectionStats)> =
                        connections.borrow().iter().map(|(&k, &s)| (k, s)).collect();
                    draw_network(terminal, target, start.elapsed(), rows)?;
                }
                View::Memory => {
                    draw_memory(terminal, target, start.elapsed(), memory_target)?;
                }
            }
            last_draw = Instant::now();
        }
    }

    Ok(())
}

fn draw_syscalls(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    target: &str,
    uptime: Duration,
    sort_by: SortBy,
    mut rows: Vec<(u64, crate::SyscallStats)>,
) -> anyhow::Result<()> {
    match sort_by {
        SortBy::Count => rows.sort_by(|a, b| b.1.count.cmp(&a.1.count)),
        SortBy::Time => rows.sort_by(|a, b| b.1.total_ns.cmp(&a.1.total_ns)),
    }

    let total_events: u64 = rows.iter().map(|(_, s)| s.count).sum();
    let sort_label = match sort_by {
        SortBy::Count => "count",
        SortBy::Time => "total time",
    };

    terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

        let header_text = format!(
            "{target}  |  uptime {}s  |  {total_events} syscalls seen  |  sorted by {sort_label} ('s' to toggle, Tab to cycle panels)",
            uptime.as_secs(),
        );
        frame.render_widget(
            Paragraph::new(header_text)
                .block(Block::default().borders(Borders::ALL).title("peekbeam — Syscalls")),
            chunks[0],
        );

        let table_rows: Vec<Row> = rows
            .iter()
            .map(|(nr, stats)| {
                let info = syscall_table::lookup(*nr);
                let notable = stats.avg_ns() > 10_000_000 || stats.count > 10_000;
                let style = if notable {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(info.category),
                    Cell::from(info.name),
                    Cell::from(stats.count.to_string()),
                    Cell::from(format!("{:.2}", stats.total_ns as f64 / 1000.0)),
                    Cell::from(format!("{:.2}", stats.avg_ns() as f64 / 1000.0)),
                    Cell::from(info.annotation),
                ])
                .style(style)
            })
            .collect();

        let widths = [
            Constraint::Length(15),
            Constraint::Length(18),
            Constraint::Length(9),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Min(24),
        ];

        let header_style = Style::default().add_modifier(Modifier::BOLD);
        let table = Table::new(table_rows, widths)
            .header(
                Row::new(vec![
                    "Category",
                    "Syscall",
                    "Count",
                    "Total (us)",
                    "Avg (us)",
                    "What it means",
                ])
                .style(header_style),
            )
            .block(Block::default().borders(Borders::ALL));

        frame.render_widget(table, chunks[1]);

        frame.render_widget(
            Paragraph::new("Ctrl+C or 'q' to quit — detaches all probes cleanly"),
            chunks[2],
        );
    })?;

    Ok(())
}

fn draw_network(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    target: &str,
    uptime: Duration,
    mut rows: Vec<(ConnectionKey, ConnectionStats)>,
) -> anyhow::Result<()> {
    rows.sort_by(|a, b| b.1.retransmits.cmp(&a.1.retransmits));
    let retransmitting = rows.iter().filter(|(_, s)| s.retransmits > 0).count();

    terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

        let header_text = format!(
            "{target}  |  uptime {}s  |  {} connections, {retransmitting} retransmitting  |  (Tab to cycle panels)",
            uptime.as_secs(),
            rows.len(),
        );
        frame.render_widget(
            Paragraph::new(header_text)
                .block(Block::default().borders(Borders::ALL).title("peekbeam — Network")),
            chunks[0],
        );

        let table_rows: Vec<Row> = rows
            .iter()
            .map(|(key, stats)| {
                let style = if stats.retransmits > 0 {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(format!(
                        "{}:{}",
                        net_table::format_addr(key.family, &key.saddr),
                        key.sport
                    )),
                    Cell::from(format!(
                        "{}:{}",
                        net_table::format_addr(key.family, &key.daddr),
                        key.dport
                    )),
                    Cell::from(net_table::state_name(stats.state)),
                    Cell::from(stats.retransmits.to_string()),
                    Cell::from(net_table::state_annotation(stats.state)),
                ])
                .style(style)
            })
            .collect();

        let widths = [
            Constraint::Length(22),
            Constraint::Length(22),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Min(24),
        ];

        let header_style = Style::default().add_modifier(Modifier::BOLD);
        let table = Table::new(table_rows, widths)
            .header(
                Row::new(vec!["Local", "Remote", "State", "Retransmits", "What it means"])
                    .style(header_style),
            )
            .block(Block::default().borders(Borders::ALL));

        frame.render_widget(table, chunks[1]);

        frame.render_widget(
            Paragraph::new(
                "Ctrl+C or 'q' to quit — detaches all probes cleanly. Bytes sent/received not available on this host (no kernel BTF for a CO-RE socket-stats read).",
            ),
            chunks[2],
        );
    })?;

    Ok(())
}

/// FR5.3: cgroup memory stats, re-read from cgroupfs on every redraw (already
/// throttled to `refresh`) rather than tracked incrementally like the other
/// two panels.
fn draw_memory(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    target: &str,
    uptime: Duration,
    memory_target: &mem_stats::MemoryTarget,
) -> anyhow::Result<()> {
    let report = mem_stats::read(memory_target);

    terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

        let header_text = format!(
            "{target}  |  uptime {}s  |  (Tab to cycle panels)",
            uptime.as_secs(),
        );
        frame.render_widget(
            Paragraph::new(header_text)
                .block(Block::default().borders(Borders::ALL).title("peekbeam — Memory")),
            chunks[0],
        );

        let (table_rows, footer): (Vec<Row>, &str) = match &report {
            Err(_) => (
                Vec::new(),
                "unavailable: no live processes found for this target (may have exited)",
            ),
            Ok(mem_stats::MemReport::Cgroup {
                current_bytes,
                anon_bytes,
                file_bytes,
                active_anon_bytes,
                inactive_anon_bytes,
            }) => {
                let rows = vec![
                    Row::new(vec![
                        Cell::from("Total (memory.current)"),
                        Cell::from(mem_stats::format_bytes(*current_bytes)),
                        Cell::from("charged to this cgroup: anon + file cache + kernel structures"),
                    ]),
                    Row::new(vec![
                        Cell::from("Anonymous"),
                        Cell::from(mem_stats::format_bytes(*anon_bytes)),
                        Cell::from("heap/stack memory, not backed by a file"),
                    ]),
                    Row::new(vec![
                        Cell::from("File cache"),
                        Cell::from(mem_stats::format_bytes(*file_bytes)),
                        Cell::from("file-backed memory, reclaimable under pressure"),
                    ]),
                    Row::new(vec![
                        Cell::from("Active anon"),
                        Cell::from(mem_stats::format_bytes(*active_anon_bytes)),
                        Cell::from("anon memory used recently, unlikely to be reclaimed soon"),
                    ]),
                    Row::new(vec![
                        Cell::from("Inactive anon"),
                        Cell::from(mem_stats::format_bytes(*inactive_anon_bytes)),
                        Cell::from("anon memory not used recently, first candidate if swap is needed"),
                    ]),
                ];
                (
                    rows,
                    "Source: cgroup memory controller. Page faults / alloc rate (FR5.1/5.2) need kernel BTF, not available on this host.",
                )
            }
            Ok(mem_stats::MemReport::Process {
                rss_bytes,
                anon_bytes,
                file_bytes,
                shmem_bytes,
                num_processes,
            }) => {
                let rows = vec![
                    Row::new(vec![
                        Cell::from("RSS (VmRSS)"),
                        Cell::from(mem_stats::format_bytes(*rss_bytes)),
                        Cell::from(format!("resident memory summed across {num_processes} process(es)")),
                    ]),
                    Row::new(vec![
                        Cell::from("Anonymous"),
                        Cell::from(mem_stats::format_bytes(*anon_bytes)),
                        Cell::from("heap/stack memory, not backed by a file"),
                    ]),
                    Row::new(vec![
                        Cell::from("File-backed"),
                        Cell::from(mem_stats::format_bytes(*file_bytes)),
                        Cell::from("mapped/cached file pages, reclaimable under pressure"),
                    ]),
                    Row::new(vec![
                        Cell::from("Shared"),
                        Cell::from(mem_stats::format_bytes(*shmem_bytes)),
                        Cell::from("shared memory (tmpfs, shm segments)"),
                    ]),
                ];
                (
                    rows,
                    "Source: /proc/<pid>/status (cgroup memory controller not delegated on this host). Page faults / alloc rate (FR5.1/5.2) need kernel BTF, not available on this host.",
                )
            }
        };

        let widths = [
            Constraint::Length(24),
            Constraint::Length(12),
            Constraint::Min(30),
        ];

        let header_style = Style::default().add_modifier(Modifier::BOLD);
        let table = Table::new(table_rows, widths)
            .header(Row::new(vec!["Metric", "Value", "What it means"]).style(header_style))
            .block(Block::default().borders(Borders::ALL));

        frame.render_widget(table, chunks[1]);
        frame.render_widget(Paragraph::new(footer), chunks[2]);
    })?;

    Ok(())
}
