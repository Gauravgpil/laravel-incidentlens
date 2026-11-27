use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use incidentlens_core::{EvidenceKind, Finding, Incident, ResponseEnvelope, Severity};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Sparkline, Wrap,
};
use ratatui::{Frame, Terminal};
use std::io;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeverityFilter {
    All,
    CriticalAndHigh,
    MediumAndAbove,
}

impl SeverityFilter {
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::CriticalAndHigh,
            Self::CriticalAndHigh => Self::MediumAndAbove,
            Self::MediumAndAbove => Self::All,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::CriticalAndHigh => "High+",
            Self::MediumAndAbove => "Med+",
        }
    }

    pub fn matches(self, sev: Severity) -> bool {
        match self {
            Self::All => true,
            Self::CriticalAndHigh => matches!(sev, Severity::Critical | Severity::High),
            Self::MediumAndAbove => {
                matches!(sev, Severity::Critical | Severity::High | Severity::Medium)
            }
        }
    }
}

pub const MODULES: &[(&str, &str)] = &[
    ("all", "Overview & All"),
    ("project", "Project Intelligence"),
    ("logs", "Log Intelligence"),
    ("code", "Code Intelligence"),
    ("architecture", "Architecture & Graph"),
    ("framework", "Framework & Octane"),
    ("database", "Database Intelligence"),
    ("api", "API Intelligence"),
    ("queue", "Queue Intelligence"),
    ("cache", "Cache Intelligence"),
    ("performance", "Performance Intelligence"),
    ("security", "Security Intelligence"),
    ("scheduler", "Scheduler Intelligence"),
    ("resources", "Memory & Disk"),
    ("scalability", "Scalability & Infra"),
    ("frontend", "Frontend & Assets"),
    ("tests", "Testing Intelligence"),
    ("deployment", "Deployment & Git"),
    ("migration", "Migration Intelligence"),
    ("dependencies", "Dependency Intelligence"),
    ("regression", "Regression Intelligence"),
];

pub struct TuiState {
    pub data: ResponseEnvelope,
    pub module_idx: usize,
    pub selected_finding: usize,
    pub search_mode: bool,
    pub search_query: String,
    pub severity_filter: SeverityFilter,
    pub show_detail: bool,
    pub show_help: bool,
    pub show_palette: bool,
    pub palette_idx: usize,
    pub status_banner: Option<String>,
}

const PALETTE_ITEMS: &[(&str, &str)] = &[
    ("all", "Overview & All Modules"),
    ("security", "Security: Secrets, AI Keys, SQLi, XSS, IDOR"),
    ("database", "Database & N+1 Query Intelligence"),
    ("logs", "Log Intelligence & Stack Traces"),
    ("performance", "Performance (P50/P95/P99 & Cache)"),
    ("code", "Code Quality (Routes, Controllers, Models)"),
    ("architecture", "Architecture & Circular Dependencies"),
    ("resources", "Memory & Disk Resources"),
    ("scalability", "Horizontal Scalability & Infra"),
    ("frontend", "Frontend & Vite/React/Inertia Assets"),
    ("migration", "Database Migration Risks"),
    ("refresh", "Refresh Diagnostics Now"),
];

impl TuiState {
    pub fn new(data: ResponseEnvelope) -> Self {
        Self {
            data,
            module_idx: 0,
            selected_finding: 0,
            search_mode: false,
            search_query: String::new(),
            severity_filter: SeverityFilter::All,
            show_detail: false,
            show_help: false,
            show_palette: false,
            palette_idx: 0,
            status_banner: None,
        }
    }

    pub fn filtered_findings(&self) -> Vec<&Finding> {
        let active_module = MODULES[self.module_idx].0;
        let query_lower = self.search_query.to_ascii_lowercase();

        self.data
            .findings
            .iter()
            .filter(|f| active_module == "all" || f.module == active_module)
            .filter(|f| self.severity_filter.matches(f.severity))
            .filter(|f| {
                query_lower.is_empty()
                    || f.title.to_ascii_lowercase().contains(&query_lower)
                    || f.id.to_ascii_lowercase().contains(&query_lower)
                    || f.affected_component
                        .to_ascii_lowercase()
                        .contains(&query_lower)
            })
            .collect()
    }

    pub fn move_down(&mut self) {
        let len = self.filtered_findings().len();
        if len > 0 {
            self.selected_finding = (self.selected_finding + 1).min(len - 1);
        }
    }

    pub fn move_up(&mut self) {
        self.selected_finding = self.selected_finding.saturating_sub(1);
    }

    pub fn next_module(&mut self) {
        self.module_idx = (self.module_idx + 1) % MODULES.len();
        self.selected_finding = 0;
    }

    pub fn prev_module(&mut self) {
        self.module_idx = if self.module_idx == 0 {
            MODULES.len() - 1
        } else {
            self.module_idx - 1
        };
        self.selected_finding = 0;
    }

    pub fn jump_module(&mut self, idx: usize) {
        if idx < MODULES.len() {
            self.module_idx = idx;
            self.selected_finding = 0;
        }
    }

    pub fn count_for_module(&self, module_key: &str) -> usize {
        if module_key == "all" {
            self.data.findings.len()
        } else {
            self.data
                .findings
                .iter()
                .filter(|f| f.module == module_key)
                .count()
        }
    }
}

pub fn run_tui<F, E>(initial: ResponseEnvelope, mut refresh_fn: F, mut export_md_fn: E) -> io::Result<()>
where
    F: FnMut() -> Option<ResponseEnvelope>,
    E: FnMut(&ResponseEnvelope) -> Result<String, String>,
{
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = TuiState::new(initial);
    let res = event_loop(&mut terminal, &mut state, &mut refresh_fn, &mut export_md_fn);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

fn event_loop<F, E>(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut TuiState,
    refresh_fn: &mut F,
    export_md_fn: &mut E,
) -> io::Result<()>
where
    F: FnMut() -> Option<ResponseEnvelope>,
    E: FnMut(&ResponseEnvelope) -> Result<String, String>,
{
    loop {
        terminal.draw(|f| draw_ui(f, state))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                if state.search_mode {
                    match key.code {
                        KeyCode::Esc | KeyCode::Enter => state.search_mode = false,
                        KeyCode::Backspace => {
                            state.search_query.pop();
                            state.selected_finding = 0;
                        }
                        KeyCode::Char(c) => {
                            state.search_query.push(c);
                            state.selected_finding = 0;
                        }
                        _ => {}
                    }
                    continue;
                }

                if state.show_palette {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('c') => state.show_palette = false,
                        KeyCode::Down | KeyCode::Char('j') => {
                            state.palette_idx = (state.palette_idx + 1).min(PALETTE_ITEMS.len() - 1);
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            state.palette_idx = state.palette_idx.saturating_sub(1);
                        }
                        KeyCode::Enter => {
                            let (key_name, label) = PALETTE_ITEMS[state.palette_idx];
                            state.show_palette = false;
                            if key_name == "refresh" {
                                if let Some(updated) = refresh_fn() {
                                    state.data = updated;
                                    state.selected_finding = 0;
                                    state.status_banner = Some("Diagnostics refreshed".to_string());
                                }
                            } else if let Some(pos) = MODULES.iter().position(|(k, _)| *k == key_name) {
                                state.jump_module(pos);
                                state.status_banner = Some(format!("Switched to {label}"));
                            }
                        }
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Char('c') => state.show_palette = !state.show_palette,
                    KeyCode::Char('?') => state.show_help = !state.show_help,
                    KeyCode::Esc => {
                        if state.show_help {
                            state.show_help = false;
                        } else if state.show_detail {
                            state.show_detail = false;
                        } else if !state.search_query.is_empty() {
                            state.search_query.clear();
                            state.selected_finding = 0;
                        }
                    }
                    KeyCode::Enter => {
                        if !state.filtered_findings().is_empty() {
                            state.show_detail = !state.show_detail;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => state.move_down(),
                    KeyCode::Up | KeyCode::Char('k') => state.move_up(),
                    KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => state.next_module(),
                    KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => state.prev_module(),
                    KeyCode::Char(c @ '0'..='9') => {
                        let idx = (c as usize) - ('0' as usize);
                        state.jump_module(idx);
                    }
                    KeyCode::Char('/') => state.search_mode = true,
                    KeyCode::Char('f') => {
                        state.severity_filter = state.severity_filter.next();
                        state.selected_finding = 0;
                    }
                    KeyCode::Char('r') => {
                        if let Some(updated) = refresh_fn() {
                            state.data = updated;
                            state.selected_finding = 0;
                            state.status_banner = Some("Diagnostics refreshed".to_string());
                        }
                    }
                    KeyCode::Char('e') => match export_md_fn(&state.data) {
                        Ok(path) => {
                            state.status_banner = Some(format!("Exported Markdown to {path}"));
                        }
                        Err(err) => {
                            state.status_banner = Some(format!("Export failed: {err}"));
                        }
                    },
                    _ => {}
                }
            }
        }
    }
}

fn draw_ui(f: &mut Frame<'_>, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(4), // Telemetry Strip: Health Gauge + KPIs + Sparkline
            Constraint::Min(10),   // Main Body
            Constraint::Length(2), // Footer
        ])
        .split(f.area());

    draw_header(f, chunks[0], state);
    draw_telemetry_strip(f, chunks[1], state);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(28), Constraint::Min(45)])
        .split(chunks[2]);

    draw_sidebar(f, body[0], state);

    if body[1].width >= 82 {
        let split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(body[1]);
        draw_findings_panel(f, split[0], state);
        draw_inline_inspector(f, split[1], state);
    } else {
        draw_findings_panel(f, body[1], state);
    }

    draw_footer(f, chunks[3], state);

    if state.show_detail {
        if let Some(finding) = state.filtered_findings().get(state.selected_finding).copied() {
            draw_detail_modal(f, finding);
        }
    }

    if state.show_help {
        draw_help_modal(f);
    }

    if state.show_palette {
        draw_palette_modal(f, state);
    }
}

fn draw_header(f: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let proj_name = state
        .data
        .project
        .as_ref()
        .map(|p| p.name.as_str())
        .unwrap_or("Laravel Application");
    let env_name = state
        .data
        .project
        .as_ref()
        .and_then(|p| p.environment.as_deref())
        .unwrap_or("unknown");
    let env_color = if env_name.eq_ignore_ascii_case("production") {
        Color::LightRed
    } else {
        Color::LightGreen
    };

    let mut spans = vec![
        Span::styled(
            "  INCIDENTLENS ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            proj_name,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  |  Env: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            env_name.to_uppercase(),
            Style::default().fg(env_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  |  v{}", state.data.engine_version),
            Style::default().fg(Color::Cyan),
        ),
    ];

    if let Some(p95) = state.data.telemetry.p95_ms {
        spans.push(Span::styled(
            format!("  |  P95: {p95:.0}ms"),
            Style::default().fg(Color::LightMagenta),
        ));
    }
    if let Some(hit) = state.data.telemetry.cache_hit_rate {
        spans.push(Span::styled(
            format!("  |  Cache Hit: {hit:.0}%"),
            Style::default().fg(Color::LightGreen),
        ));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));
    f.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

fn draw_telemetry_strip(f: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(22), // Health Gauge
            Constraint::Percentage(13), // Errors
            Constraint::Percentage(13), // Warnings
            Constraint::Percentage(13), // Perf
            Constraint::Percentage(13), // Security
            Constraint::Percentage(26), // Sparkline
        ])
        .split(area);

    let score = state.data.telemetry.health_score;
    let gauge_color = if score >= 85 {
        Color::LightGreen
    } else if score >= 60 {
        Color::Yellow
    } else {
        Color::LightRed
    };
    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(" HEALTH SCORE ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(gauge_color)),
        )
        .gauge_style(Style::default().fg(gauge_color).bg(Color::DarkGray))
        .percent(score as u16)
        .label(format!("{score}/100"));
    f.render_widget(gauge, cols[0]);

    let s = &state.data.summary;
    render_kpi_card(f, cols[1], "ERRORS", s.errors, Color::LightRed);
    render_kpi_card(f, cols[2], "WARNS", s.warnings, Color::Yellow);
    render_kpi_card(f, cols[3], "PERF", s.performance, Color::Magenta);
    render_kpi_card(f, cols[4], "SECURITY", s.security, Color::LightCyan);

    let timeline_data: Vec<u64> = if state.data.telemetry.log_timeline.is_empty() {
        vec![
            s.errors as u64,
            s.warnings as u64,
            s.performance as u64,
            s.security as u64,
            state.data.incidents.len() as u64,
        ]
    } else {
        state.data.telemetry.log_timeline.clone()
    };

    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .title(" ACTIVITY TREND ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::LightMagenta)),
        )
        .data(&timeline_data)
        .style(Style::default().fg(Color::LightMagenta));
    f.render_widget(sparkline, cols[5]);
}

fn render_kpi_card(f: &mut Frame<'_>, area: Rect, label: &str, count: usize, color: Color) {
    let block = Block::default()
        .title(Span::styled(
            format!(" {label} "),
            Style::default().fg(Color::Gray).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color));

    let text = Paragraph::new(Line::from(Span::styled(
        format!(" {count}"),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )))
    .block(block);
    f.render_widget(text, area);
}

fn draw_sidebar(f: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let items: Vec<ListItem<'_>> = MODULES
        .iter()
        .enumerate()
        .map(|(idx, (key, label))| {
            let count = state.count_for_module(key);
            let style = if idx == state.module_idx {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let prefix = if idx <= 9 {
                format!("[{idx}]")
            } else {
                "   ".to_string()
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {prefix} {:<17}", truncate_str(label, 17)), style),
                Span::styled(
                    format!("{:>4} ", count),
                    if idx == state.module_idx {
                        style
                    } else if count > 0 {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    },
                ),
            ]))
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(state.module_idx));

    let list = List::new(items).block(
        Block::default()
            .title(" Modules (0-9) ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_stateful_widget(list, area, &mut list_state);
}

fn draw_findings_panel(f: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let filtered = state.filtered_findings();
    let title = format!(
        " {} ({}) | Filter: {} {} ",
        MODULES[state.module_idx].1,
        filtered.len(),
        state.severity_filter.label(),
        if state.search_query.is_empty() {
            String::new()
        } else {
            format!("| Search: \"{}\"", state.search_query)
        }
    );

    let block = Block::default()
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));

    if filtered.is_empty() {
        let msg = if !state.data.incidents.is_empty() && state.module_idx == 0 {
            render_incidents_summary(&state.data.incidents)
        } else {
            "✓ No findings match the current module and filter.".to_string()
        };
        f.render_widget(
            Paragraph::new(msg)
                .style(Style::default().fg(Color::Green))
                .block(block)
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let items: Vec<ListItem<'_>> = filtered
        .iter()
        .map(|finding| {
            let (sev_label, sev_color) = severity_badge(finding.severity);
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {sev_label} "),
                    Style::default()
                        .fg(Color::Black)
                        .bg(sev_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(
                    format!("[{}] ", finding.id),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(finding.title.clone(), Style::default().fg(Color::White)),
            ]))
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(state.selected_finding));

    let list = List::new(items)
        .block(block)
        .highlight_symbol("▌")
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, area, &mut list_state);

    let mut scroll_state = ScrollbarState::new(filtered.len()).position(state.selected_finding);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight);
    f.render_stateful_widget(scrollbar, area, &mut scroll_state);
}

fn draw_inline_inspector(f: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let block = Block::default()
        .title(" Live Inspector ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Magenta));

    let Some(finding) = state.filtered_findings().get(state.selected_finding).copied() else {
        f.render_widget(
            Paragraph::new("Select a finding to inspect evidence and code context.")
                .style(Style::default().fg(Color::DarkGray))
                .block(block),
            area,
        );
        return;
    };

    let lines = build_finding_lines(finding);
    f.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: false }),
        area,
    );
}

fn build_finding_lines(finding: &Finding) -> Vec<Line<'_>> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled("ID: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                &finding.id,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" | "),
            Span::styled(&finding.module, Style::default().fg(Color::Yellow)),
            Span::raw(" | Conf: "),
            Span::styled(
                format!("{:?}", finding.confidence),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(Span::styled(
            &finding.title,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("Component: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&finding.affected_component, Style::default().fg(Color::LightBlue)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Evidence:",
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        )),
    ];

    for ev in &finding.evidence {
        if ev.source == "code_frame" {
            lines.push(Line::from(Span::styled(
                "Code Frame:",
                Style::default().fg(Color::Yellow),
            )));
            for code_line in ev.detail.lines() {
                let style = if code_line.starts_with(">>") {
                    Style::default()
                        .fg(Color::LightRed)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                };
                lines.push(Line::from(Span::styled(format!("  {code_line}"), style)));
            }
        } else {
            let kind_color = match ev.kind {
                EvidenceKind::Observed => Color::Green,
                EvidenceKind::Correlated => Color::Magenta,
                EvidenceKind::Hypothesis => Color::Yellow,
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  • [{:?}] ", ev.kind), Style::default().fg(kind_color)),
                Span::raw(&ev.detail),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Recommended Next Step:",
        Style::default()
            .fg(Color::LightGreen)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(Span::styled(
        format!("  {}", finding.next_step),
        Style::default().fg(Color::White),
    )));
    lines
}

fn render_incidents_summary(incidents: &[Incident]) -> String {
    let mut out = String::from("Correlated Incidents:\n");
    for inc in incidents {
        out.push_str(&format!("- [{}] {}: {}\n", inc.id, inc.title, inc.possible_root_cause));
    }
    out
}

fn draw_footer(f: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let text = if state.search_mode {
        format!(" Search: {}_  (Enter/Esc to finish)", state.search_query)
    } else if let Some(ref banner) = state.status_banner {
        format!(" {banner}  |  [q] Quit  [?] Help")
    } else {
        " [↑/↓] Nav  [c] Palette  [e] Export .md  [Enter] Modal  [/] Search  [f] Filter  [r] Refresh  [q] Quit".to_string()
    };

    f.render_widget(
        Paragraph::new(text).style(Style::default().fg(Color::Cyan)),
        area,
    );
}

fn draw_detail_modal(f: &mut Frame<'_>, finding: &Finding) {
    let area = centered_rect(78, 74, f.area());
    f.render_widget(Clear, area);

    let modal = Paragraph::new(build_finding_lines(finding))
        .block(
            Block::default()
                .title(" Finding Inspector (Esc to close) ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::LightCyan)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(modal, area);
}

fn draw_help_modal(f: &mut Frame<'_>) {
    let area = centered_rect(58, 52, f.area());
    f.render_widget(Clear, area);

    let help_text = "\
  Keyboard Shortcuts:
    ↑ / ↓ / j / k   Navigate findings
    Tab / ← / →     Switch diagnostic module
    0 .. 9          Quick-jump to module
    Enter           Toggle full-screen finding modal
    /               Live search findings
    f               Cycle severity filter (All / High+ / Med+)
    r               Refresh diagnostics
    Esc             Close modal or clear search
    q               Quit IncidentLens";

    let modal = Paragraph::new(help_text).block(
        Block::default()
            .title(" Help (Esc or ? to close) ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    f.render_widget(modal, area);
}

fn draw_palette_modal(f: &mut Frame<'_>, state: &TuiState) {
    let area = centered_rect(64, 62, f.area());
    f.render_widget(Clear, area);

    let items: Vec<ListItem<'_>> = PALETTE_ITEMS
        .iter()
        .enumerate()
        .map(|(i, (_, label))| {
            let style = if i == state.palette_idx {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(Line::from(Span::styled(format!("  {label}  "), style)))
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(state.palette_idx));

    let list = List::new(items).block(
        Block::default()
            .title(" Command Palette (↑/↓ + Enter to run, Esc to close) ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::LightCyan)),
    );
    f.render_stateful_widget(list, area, &mut list_state);
}

fn severity_badge(sev: Severity) -> (&'static str, Color) {
    match sev {
        Severity::Critical => ("CRIT", Color::Red),
        Severity::High => ("HIGH", Color::LightRed),
        Severity::Medium => ("MED ", Color::Yellow),
        Severity::Low => ("LOW ", Color::Blue),
        Severity::Info => ("INFO", Color::Gray),
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use incidentlens_core::{Confidence, Finding};

    #[test]
    fn tui_state_filters_by_module_severity_and_search() {
        let resp = ResponseEnvelope::ok(
            None,
            vec![
                Finding {
                    id: "LOG-001".into(),
                    module: "logs".into(),
                    title: "SQLSTATE deadlock".into(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    affected_component: "OrderService".into(),
                    evidence: vec![],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Check query".into(),
                },
                Finding {
                    id: "PRJ-004".into(),
                    module: "project".into(),
                    title: "Missing composer.lock".into(),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    affected_component: "composer.lock".into(),
                    evidence: vec![],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Run composer install".into(),
                },
            ],
        );

        let mut state = TuiState::new(resp);
        assert_eq!(state.filtered_findings().len(), 2);

        state.severity_filter = SeverityFilter::CriticalAndHigh;
        assert_eq!(state.filtered_findings().len(), 1);
        assert_eq!(state.filtered_findings()[0].id, "LOG-001");

        state.severity_filter = SeverityFilter::All;
        state.search_query = "composer".into();
        assert_eq!(state.filtered_findings().len(), 1);
        assert_eq!(state.filtered_findings()[0].id, "PRJ-004");
    }
}
