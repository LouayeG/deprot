//! Rendering: draw the current [`App`] state into a ratatui [`Frame`]. No input handling and no
//! terminal setup here — just state → widgets, which keeps it easy to snapshot-test. The `anim`
//! parameter (0.0–1.0) drives the signal-fill animation when the selection changes.

use crate::app::App;
use crate::theme;
use deprot_core::{Grade, Signal};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Bar, BarChart, BarGroup, Block, BorderType, Borders, Cell, Clear, Gauge, Paragraph,
        Row as TableRow, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState, Wrap,
    },
    Frame,
};

/// A rounded, dim-bordered block with a title — the standard panel chrome.
fn panel(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::DIM))
        .title(Span::styled(
            title,
            Style::default().fg(theme::DIM).add_modifier(Modifier::BOLD),
        ))
}

/// Letter grade for a 0–100 value (mirrors the core thresholds for the hero gauge label).
fn grade_for(value: u8) -> Grade {
    match value {
        90..=100 => Grade::A,
        75..=89 => Grade::B,
        60..=74 => Grade::C,
        40..=59 => Grade::D,
        _ => Grade::F,
    }
}

/// Draw the whole UI at animation phase `anim` (0.0 = just selected, 1.0 = settled).
pub fn draw(f: &mut Frame, app: &App, anim: f64) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // hero gauge
            Constraint::Min(3),    // body
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    draw_hero(f, app, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[1]);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(9)])
        .split(body[0]);

    draw_list(f, app, left[0]);
    draw_chart(f, app, left[1]);
    draw_detail(f, app, body[1], anim);

    draw_footer(f, app, chunks[2]);

    if app.show_help {
        draw_help(f, f.area());
    }
}

/// The project-health hero gauge across the top.
fn draw_hero(f: &mut Frame, app: &App, area: Rect) {
    let overall = app.overall_score();
    let (ok, caution, risky) = app.counts();
    let grade = grade_for(overall);
    let ratio = (overall as f64 / 100.0).clamp(0.0, 1.0);
    let label = format!(
        "{overall}/100  ·  grade {}  ·  {risky} risky  {caution} caution  {ok} ok",
        grade.as_str()
    );
    let gauge = Gauge::default()
        .block(panel(" DEPROT · project health "))
        .gauge_style(
            Style::default()
                .fg(theme::health_color(ratio))
                .bg(theme::DIM),
        )
        .ratio(ratio)
        .label(Span::styled(
            label,
            Style::default()
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        ));
    f.render_widget(gauge, area);
}

/// The navigable dependency list, with a highlighted selection and a scrollbar.
fn draw_list(f: &mut Frame, app: &App, area: Rect) {
    // In a merged --recursive view, an extra column tags each row with its subproject.
    let show_source = app.has_sources();
    let rows = app.visible().map(|r| {
        let tc = theme::tier_color(r.score.tier);
        let mut cells = vec![
            Cell::from(Span::styled(
                r.dependency.name.clone(),
                Style::default().fg(theme::INK),
            )),
            Cell::from(Span::styled(
                format!("{:>3}", r.score.value),
                Style::default().fg(tc),
            )),
            Cell::from(Span::styled(
                r.score.grade.as_str(),
                Style::default().fg(theme::grade_color(r.score.grade)),
            )),
            Cell::from(Span::styled(
                r.score.tier.as_str().to_uppercase(),
                Style::default().fg(tc),
            )),
        ];
        if show_source {
            cells.push(Cell::from(Span::styled(
                r.source.clone().unwrap_or_default(),
                Style::default().fg(theme::DIM),
            )));
        }
        TableRow::new(cells)
    });

    let title = if app.query.is_empty() {
        " dependencies ".to_string()
    } else {
        format!(" dependencies · /{} ", app.query)
    };

    let mut header = vec!["PACKAGE", "SCR", "GRD", "VERDICT"];
    let mut widths = vec![
        Constraint::Min(10),
        Constraint::Length(4),
        Constraint::Length(5),
        Constraint::Length(8),
    ];
    if show_source {
        header.push("SUBPROJECT");
        widths.push(Constraint::Length(14));
    }

    let table = Table::new(rows, widths)
        .header(TableRow::new(header).style(Style::default().fg(theme::DIM)))
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(40, 44, 52))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▍ ")
        .block(panel(&title));

    let mut state = TableState::default().with_selected(Some(app.selected));
    f.render_stateful_widget(table, area, &mut state);

    // Scrollbar on the right edge of the panel.
    if app.visible_len() > area.height.saturating_sub(3) as usize {
        let mut sb_state = ScrollbarState::new(app.visible_len()).position(app.selected);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .style(Style::default().fg(theme::DIM)),
            area,
            &mut sb_state,
        );
    }
}

/// A bar chart of how many dependencies fall in each letter grade (A→F), colored on the grade
/// ramp and directly labeled with counts.
fn draw_chart(f: &mut Frame, app: &App, area: Rect) {
    let mut counts = [0u64; 5];
    for r in app.visible() {
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
            let c = theme::grade_color(*g);
            Bar::default()
                .value(n)
                .label(Line::from(g.as_str()))
                .text_value(n.to_string())
                .style(Style::default().fg(c))
                .value_style(
                    Style::default()
                        .fg(Color::Black)
                        .bg(c)
                        .add_modifier(Modifier::BOLD),
                )
        })
        .collect();

    let chart = BarChart::default()
        .block(panel(" grade distribution "))
        .data(BarGroup::default().bars(&bars))
        .bar_width(5)
        .bar_gap(2);
    f.render_widget(chart, area);
}

/// The detail pane: a big block-letter grade hero, headline stats, forced reasons, and the
/// animated signal breakdown for the selected package.
fn draw_detail(f: &mut Frame, app: &App, area: Rect, anim: f64) {
    let block = panel(" details ");
    let Some(row) = app.current() else {
        f.render_widget(
            Paragraph::new("no dependencies match the current filter")
                .style(Style::default().fg(theme::DIM))
                .block(block),
            area,
        );
        return;
    };
    let s = &row.score;
    let gc = theme::grade_color(s.grade);
    let tc = theme::tier_color(s.tier);

    let mut lines: Vec<Line> = Vec::new();

    // Big block-letter grade hero, with the headline stats stacked beside it.
    let art = theme::grade_block(s.grade);
    let info = [
        (0usize, Line::from("")),
        (
            1,
            Line::from(Span::styled(
                row.dependency.name.clone(),
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            )),
        ),
        (
            2,
            Line::from(Span::styled(
                row.analyzed_version.clone().unwrap_or_else(|| "?".into()),
                Style::default().fg(theme::DIM),
            )),
        ),
        (
            3,
            Line::from(vec![
                Span::styled(
                    format!("{}/100", s.value),
                    Style::default().fg(tc).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  [{}]", s.tier.as_str().to_uppercase()),
                    Style::default().fg(tc),
                ),
            ]),
        ),
    ];
    for (i, art_line) in art.iter().enumerate() {
        let mut spans = vec![
            Span::styled((*art_line).to_string(), Style::default().fg(gc)),
            Span::raw("   "),
        ];
        if let Some((_, l)) = info.iter().find(|(row_idx, _)| *row_idx == i) {
            spans.extend(l.spans.clone());
        }
        lines.push(Line::from(spans));
    }

    if let Some(src) = &row.source {
        lines.push(Line::from(Span::styled(
            format!("from {src}"),
            Style::default().fg(theme::DIM),
        )));
    }

    if let Some(err) = &row.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("lookup failed: {err}"),
            Style::default().fg(theme::tier_color(deprot_core::Tier::Risky)),
        )));
    }

    if !s.forced_reasons.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "⚠ Forced RISKY because:",
            Style::default().fg(tc).add_modifier(Modifier::BOLD),
        )));
        for r in &s.forced_reasons {
            lines.push(Line::from(Span::styled(
                format!("   • {r}"),
                Style::default().fg(tc),
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Signals",
        Style::default().fg(theme::INK).add_modifier(Modifier::BOLD),
    )));
    for sig in &s.signals {
        lines.push(signal_line(sig, anim));
        lines.push(Line::from(Span::styled(
            format!("    {}", sig.detail),
            Style::default().fg(theme::DIM),
        )));
    }

    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: true })
            .scroll((app.detail_scroll, 0)),
        area,
    );
}

/// One signal as `name  ██████░░░░  62%`, its fill scaled by `anim` so it grows in on selection.
fn signal_line(sig: &Signal, anim: f64) -> Line<'static> {
    let shown = sig.score * anim.clamp(0.0, 1.0);
    let filled = (shown * 10.0).round() as usize;
    let bar: String = "█".repeat(filled) + &"░".repeat(10usize.saturating_sub(filled));
    let color = theme::health_color(sig.score);
    Line::from(vec![
        Span::styled(format!("{:<16}", sig.name), Style::default().fg(theme::INK)),
        Span::styled(bar, Style::default().fg(color)),
        Span::styled(
            format!(" {:>3.0}%", sig.score * 100.0),
            Style::default().fg(color),
        ),
    ])
}

/// Contextual footer: the search input while searching, otherwise the key hints.
fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let line = if app.searching {
        Line::from(vec![
            Span::styled(
                "/",
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(app.query.clone(), Style::default().fg(theme::INK)),
            Span::styled("▏", Style::default().fg(theme::ACCENT)),
            Span::styled(
                "   (enter to keep · esc to clear)",
                Style::default().fg(theme::DIM),
            ),
        ])
    } else {
        Line::from(Span::styled(
            format!(
                " ↑/↓ move · / search · f filter [{}] · s sort [{}] · ? help · q quit ",
                app.filter_label(),
                app.sort.label()
            ),
            Style::default().fg(theme::DIM),
        ))
    };
    f.render_widget(Paragraph::new(line), area);
}

/// A centered modal listing every keybinding.
fn draw_help(f: &mut Frame, area: Rect) {
    let width = 52u16.min(area.width.saturating_sub(4));
    let height = 14u16.min(area.height.saturating_sub(2));
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    let help = [
        ("↑ / ↓  or  j / k", "move selection"),
        ("g / G", "jump to top / bottom"),
        ("PgUp / PgDn", "scroll the details pane"),
        ("/", "search by package or subproject"),
        ("f", "cycle verdict filter (all/risky/caution+)"),
        ("s", "cycle sort (tier/score/name)"),
        ("o", "open the package's source/advisory URL"),
        ("?", "toggle this help"),
        ("q  or  Esc", "quit"),
    ];
    let mut lines = vec![Line::from(Span::styled(
        "Keybindings",
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
    ))];
    lines.push(Line::from(""));
    for (k, v) in help {
        lines.push(Line::from(vec![
            Span::styled(format!("  {k:<18}"), Style::default().fg(theme::ACCENT)),
            Span::styled(v.to_string(), Style::default().fg(theme::INK)),
        ]));
    }
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Left)
            .block(panel(" help ").border_style(Style::default().fg(theme::ACCENT))),
        rect,
    );
}

/// The startup splash: the DEPROT banner + credit + tagline, centered. `reveal` (0.0–1.0)
/// controls how many banner rows have appeared, for a quick top-down reveal.
pub fn draw_splash(f: &mut Frame, reveal: f64) {
    let area = f.area();
    f.render_widget(Clear, area);

    let banner_rows = theme::BANNER.len();
    let shown = ((reveal.clamp(0.0, 1.0) * banner_rows as f64).ceil() as usize).min(banner_rows);

    let mut lines: Vec<Line> = Vec::new();
    let pad = (area.height.saturating_sub(banner_rows as u16 + 4)) / 2;
    for _ in 0..pad {
        lines.push(Line::from(""));
    }
    for row in theme::BANNER.iter().take(shown) {
        lines.push(Line::from(Span::styled(
            (*row).to_string(),
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        )));
    }
    if reveal >= 0.99 {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            theme::CREDIT,
            Style::default().fg(theme::INK).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            theme::TAGLINE,
            Style::default().fg(theme::DIM),
        )));
    }
    f.render_widget(Paragraph::new(lines).alignment(Alignment::Center), area);
}
