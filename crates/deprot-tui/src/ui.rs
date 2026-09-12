//! Rendering: draw the current [`App`] state into a ratatui [`Frame`]. No input handling and no
//! terminal setup here — just state → widgets, which keeps it easy to snapshot-test.

use crate::app::App;
use deprot_core::{Grade, Signal, Tier};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Bar, BarChart, BarGroup, Block, Borders, Cell, Paragraph, Row as TableRow, Table, Wrap,
    },
    Frame,
};

fn tier_color(tier: Tier) -> Color {
    match tier {
        Tier::Ok => Color::Green,
        Tier::Caution => Color::Yellow,
        Tier::Risky => Color::Red,
    }
}

fn grade_color(grade: Grade) -> Color {
    match grade {
        Grade::A => Color::Green,
        Grade::B => Color::Cyan,
        Grade::C => Color::Yellow,
        Grade::D => Color::LightRed,
        Grade::F => Color::Red,
    }
}

/// Draw the whole UI: header, list+detail split, footer.
pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Min(3),    // body
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    draw_header(f, app, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[1]);

    // Left column: the dependency list on top, a grade-distribution chart beneath it.
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(9)])
        .split(body[0]);

    draw_list(f, app, left[0]);
    draw_chart(f, app, left[1]);
    draw_detail(f, app, body[1]);

    draw_footer(f, app, chunks[2]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let (ok, caution, risky) = app.counts();
    let line = Line::from(vec![
        Span::styled(
            " deprot ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" {} deps  ", app.rows.len())),
        Span::styled(format!("{risky} risky"), Style::default().fg(Color::Red)),
        Span::raw("  "),
        Span::styled(
            format!("{caution} caution"),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("  "),
        Span::styled(format!("{ok} ok"), Style::default().fg(Color::Green)),
        Span::styled(
            format!("   sort: {}", app.sort.label()),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_list(f: &mut Frame, app: &App, area: Rect) {
    let rows = app.rows.iter().enumerate().map(|(i, r)| {
        let selected = i == app.selected;
        let tc = tier_color(r.score.tier);
        let marker = if selected { "▍" } else { " " };
        let base = if selected {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        TableRow::new(vec![
            Cell::from(Span::styled(marker, Style::default().fg(tc))),
            Cell::from(Span::styled(r.dependency.name.clone(), base)),
            Cell::from(Span::styled(format!("{:>3}", r.score.value), base.fg(tc))),
            Cell::from(Span::styled(
                r.score.grade.as_str(),
                base.fg(grade_color(r.score.grade)),
            )),
            Cell::from(Span::styled(
                r.score.tier.as_str().to_uppercase(),
                base.fg(tc),
            )),
        ])
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Min(10),
            Constraint::Length(4),
            Constraint::Length(5),
            Constraint::Length(8),
        ],
    )
    .header(
        TableRow::new(vec!["", "PACKAGE", "SCR", "GRD", "VERDICT"])
            .style(Style::default().fg(Color::DarkGray)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" dependencies "),
    );

    f.render_widget(table, area);
}

/// A bar chart of how many dependencies fall in each letter grade (A→F). Grades are an ordered
/// good→bad status ramp, so each bar is colored by its own grade color (color follows the entity),
/// and each bar is directly labeled with its count — no separate legend needed.
fn draw_chart(f: &mut Frame, app: &App, area: Rect) {
    let mut counts = [0u64; 5]; // A, B, C, D, F
    for r in &app.rows {
        let idx = match r.score.grade {
            Grade::A => 0,
            Grade::B => 1,
            Grade::C => 2,
            Grade::D => 3,
            Grade::F => 4,
        };
        counts[idx] += 1;
    }
    let grades = [Grade::A, Grade::B, Grade::C, Grade::D, Grade::F];
    let bars: Vec<Bar> = grades
        .iter()
        .zip(counts)
        .map(|(g, n)| {
            Bar::default()
                .value(n)
                .label(Line::from(g.as_str()))
                .text_value(n.to_string())
                .style(Style::default().fg(grade_color(*g)))
                .value_style(
                    Style::default()
                        .fg(Color::Black)
                        .bg(grade_color(*g))
                        .add_modifier(Modifier::BOLD),
                )
        })
        .collect();

    let chart = BarChart::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" grade distribution "),
        )
        .data(BarGroup::default().bars(&bars))
        .bar_width(5)
        .bar_gap(2);

    f.render_widget(chart, area);
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" details ");
    let Some(row) = app.current() else {
        f.render_widget(Paragraph::new("no dependencies").block(block), area);
        return;
    };
    let s = &row.score;
    let tc = tier_color(s.tier);

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(
            row.dependency.name.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  {}", row.analyzed_version.as_deref().unwrap_or("?")),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::raw("score "),
        Span::styled(
            format!("{}/100", s.value),
            Style::default().fg(tc).add_modifier(Modifier::BOLD),
        ),
        Span::raw("   grade "),
        Span::styled(s.grade.as_str(), Style::default().fg(grade_color(s.grade))),
        Span::raw("   "),
        Span::styled(
            format!("[{}]", s.tier.as_str().to_uppercase()),
            Style::default().fg(tc).add_modifier(Modifier::BOLD),
        ),
    ]));

    if let Some(err) = &row.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("lookup failed: {err}"),
            Style::default().fg(Color::Red),
        )));
    }

    if !s.forced_reasons.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Forced RISKY because:",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
        for r in &s.forced_reasons {
            lines.push(Line::from(Span::styled(
                format!("  • {r}"),
                Style::default().fg(Color::Red),
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Signals",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    for sig in &s.signals {
        lines.push(signal_line(sig));
        lines.push(Line::from(Span::styled(
            format!("    {}", sig.detail),
            Style::default().fg(Color::DarkGray),
        )));
    }

    f.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

/// One signal rendered as `name  ██████░░░░  62%`, colored by health.
fn signal_line(sig: &Signal) -> Line<'static> {
    let filled = (sig.score * 10.0).round() as usize;
    let bar: String = "█".repeat(filled) + &"░".repeat(10usize.saturating_sub(filled));
    let color = if sig.score >= 0.75 {
        Color::Green
    } else if sig.score >= 0.4 {
        Color::Yellow
    } else {
        Color::Red
    };
    Line::from(vec![
        Span::styled(format!("{:<16}", sig.name), Style::default()),
        Span::styled(bar, Style::default().fg(color)),
        Span::styled(
            format!(" {:>3.0}%", sig.score * 100.0),
            Style::default().fg(color),
        ),
    ])
}

fn draw_footer(f: &mut Frame, _app: &App, area: Rect) {
    let line = Line::from(Span::styled(
        " ↑/↓ or j/k move   g/G top/bottom   s sort   q quit ",
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(Paragraph::new(line), area);
}
