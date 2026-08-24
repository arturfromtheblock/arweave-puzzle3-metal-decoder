use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
    Terminal, Frame,
};

#[derive(Clone, PartialEq)]
pub enum Status { Starting, Running, Found, NoHit, Error }

#[derive(Clone)]
pub struct AppState {
    pub status: Status,
    pub paused: bool,
    pub tested: u64,
    pub total: u128,
    pub speed: f64,
    pub elapsed: Duration,
    pub current_pass: String,
    pub panels: Vec<usize>,
    pub log: VecDeque<String>,
    pub found_pass: Option<String>,
    pub recent_passes: VecDeque<String>,
    pub batch_no: u64,
    pub updated_at: Instant,
}

impl AppState {
    pub fn push_log(&mut self, msg: String) {
        self.log.push_back(msg);
        while self.log.len() > 300 { self.log.pop_front(); }
    }
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push('.'); }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn fmt_dur(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 { return "–".into(); }
    let s = secs as u64;
    if s < 60 { format!("{}s", s) }
    else if s < 3600 { format!("{}m {:02}s", s / 60, s % 60) }
    else { format!("{}h {:02}m", s / 3600, (s % 3600) / 60) }
}

fn stat_box<'a>(title: &'a str, value: &'a str) -> Paragraph<'a> {
    use ratatui::widgets::Padding;
    Paragraph::new(value)
        .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", title))
                .padding(Padding::new(1, 1, 0, 0))
        )
}

fn draw(f: &mut Frame, st: &AppState) {
    let area = f.area();

    if area.width < 60 || area.height < 18 {
        f.render_widget(Paragraph::new("[-] Terminal too small — please enlarge (at least 60x18)"), area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(3), // Stats
            Constraint::Length(3), // Progress
            Constraint::Length(4), // Panels/Actual
            Constraint::Min(5),    // Log (flexibel!)
            Constraint::Length(3), // Footer
        ])
        .split(area);

    // Header
    let (status_txt, status_col) = match (&st.status, st.paused) {
        (_, true)              => ("⏸  Pause", Color::Yellow),
        (Status::Starting, _)  => ("… Start", Color::Cyan),
        (Status::Running, _)   => ("[*] Running", Color::Green),
        (Status::Found, _)     => ("[!] Hit", Color::Green),
        (Status::NoHit, _)     => ("[-] Done", Color::Red),
        (Status::Error, _)     => ("[-] Error", Color::Red),
    };
    let header = Paragraph::new(format!(" 🔐 Arweave Puzzle #3 Metal-Decoder by github.com/arturfromtheblock  ·   State: {}", status_txt))
        .style(Style::default().fg(status_col).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, chunks[0]);

    let pct = if st.total > 0 { (st.tested as f64 / st.total as f64 * 100.0).min(100.0) } else { 0.0 };
    let eta = if st.speed > 1.0 {
        fmt_dur(st.total.saturating_sub(st.tested as u128) as f64 / st.speed)
    } else { "–".into() };

    let stats = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(25); 4])
        .split(chunks[1]);
    f.render_widget(stat_box("⚡️ Speed", &format!("{:.0}/s", st.speed)), stats[0]);
    f.render_widget(stat_box("🔎 Tested", &fmt_num(st.tested)), stats[1]);
    f.render_widget(stat_box("🕞 Time", &format!("{}", fmt_dur(st.elapsed.as_secs_f64()))), stats[2]);
    f.render_widget(stat_box("🏁 ETA", &format!("{}", eta)), stats[3]);

    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Progress "))
        .gauge_style(Style::default().fg(Color::LightBlue))
        .percent(pct as u16);
    f.render_widget(gauge, chunks[2]);

    let panel_txt = st.panels.iter().enumerate()
        .map(|(i, n)| format!("P{}: {}", i + 1, n))
        .collect::<Vec<_>>().join("   ");
    let batch_lines = vec![
        Line::from(format!(" Panels: {}", panel_txt)),
        Line::from(Span::styled(format!(" Actual: {}", st.current_pass), Style::default().fg(Color::Yellow))),
    ];

    let cur = Paragraph::new(batch_lines)
        .block(Block::default().borders(Borders::ALL).title(" Batch "));
    f.render_widget(cur, chunks[3]);

    let visible = chunks[4].height.saturating_sub(2) as usize;
    let items: Vec<ListItem> = st.log.iter().rev().take(visible).rev()
        .map(|l| ListItem::new(l.as_str())).collect();
    f.render_widget(List::new(items).block(Block::default().borders(Borders::ALL).title(" Log ")), chunks[4]);

    let footer_txt = if matches!(st.status, Status::Found | Status::NoHit | Status::Error) {
        " [Q/ESC] QUIT   ·   RESIZE = auto   ·   Buy Bitcoin ₿"
    } else {
        " [Q/ESC] QUIT   [p] PAUSE   ·   RESIZE = auto   ·   Buy Bitcoin ₿"
    };
    let footer = Paragraph::new(footer_txt)
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[5]);
}

pub fn run(state: Arc<Mutex<AppState>>, quit: Arc<AtomicBool>) -> std::io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    let mut frame: u64 = 0;
    loop {
        frame = frame.wrapping_add(1);
        let mut st = state.lock().unwrap().clone();

        if st.status == Status::Running && !st.paused {
            st.elapsed += st.updated_at.elapsed();

            if !st.recent_passes.is_empty() {
                let idx = (frame / 2) as usize % st.recent_passes.len();
                st.current_pass = st.recent_passes[idx].clone();
            }
        }

        if st.status == Status::Found {
            if let Some(p) = &st.found_pass {
                st.current_pass = p.clone();
            }
        }

        terminal.draw(|f| draw(f, &st))?;

        if event::poll(Duration::from_millis(16))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            quit.store(true, Ordering::SeqCst);
                            break;
                        }
                        KeyCode::Char('p') => {
                            let mut s = state.lock().unwrap();
                            if s.status == Status::Running || s.status == Status::Starting {
                                let was_paused = s.paused;
                                s.paused = !was_paused;
                                s.push_log(if was_paused {
                                    "[*] Continue requested".to_string()
                                } else {
                                    "[*] Pause requested".to_string()
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}