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

use crate::{ConnMap, ConnectionKey, ConnectionStats, StatsMap, net_table, syscall_table};

#[derive(Clone, Copy, PartialEq)]
enum View {
    Syscalls,
    Network,
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

    let result = run_loop(&mut terminal, &target, refresh, stats, connections, &mut poll_events);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    target: &str,
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
                                View::Network => View::Syscalls,
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
            "{target}  |  uptime {}s  |  {total_events} syscalls seen  |  sorted by {sort_label} ('s' to toggle, Tab for Network)",
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
            "{target}  |  uptime {}s  |  {} connections, {retransmitting} retransmitting  |  (Tab for Syscalls)",
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
