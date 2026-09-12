//! # deprot-tui
//!
//! An interactive terminal UI for browsing a deprot analysis: arrow through the dependency list
//! on the left and watch the full signal breakdown for the highlighted package update live on the
//! right. State and rendering live in [`app`] and [`ui`] respectively and are terminal-free; this
//! module owns the crossterm terminal lifecycle and the input loop.

mod app;
mod ui;

pub use app::{App, Sort};

use deprot_report::Row;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

/// Launch the interactive TUI over the given scored rows. Blocks until the user quits, then
/// restores the terminal (even on error/panic, via ratatui's install hooks).
pub fn run(rows: Vec<Row>) -> anyhow::Result<()> {
    let mut app = App::new(rows);
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> anyhow::Result<()> {
    while !app.should_quit {
        terminal.draw(|f| ui::draw(f, app))?;
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                handle_key(app, key.code, key.modifiers);
            }
        }
    }
    Ok(())
}

/// Render a single frame to a plain-text string at the given size, without a real terminal.
/// Useful for documentation snapshots and previews (colors are dropped, layout is preserved).
pub fn render_to_text(rows: Vec<Row>, width: u16, height: u16) -> String {
    use ratatui::{backend::TestBackend, Terminal};
    let app = App::new(rows);
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
    terminal.draw(|f| ui::draw(f, &app)).expect("draw");
    let buffer = terminal.backend().buffer().clone();
    let mut out = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            out.push_str(buffer[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// Apply one key press to the app state.
fn handle_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    // Ctrl-C always quits.
    if mods.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }
    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Down | KeyCode::Char('j') => app.next(),
        KeyCode::Up | KeyCode::Char('k') => app.prev(),
        KeyCode::Char('g') | KeyCode::Home => app.first(),
        KeyCode::Char('G') | KeyCode::End => app.last(),
        KeyCode::Char('s') => app.cycle_sort(),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deprot_core::{score, Dependency, Ecosystem, Facts};
    use ratatui::{backend::TestBackend, Terminal};

    fn sample_rows() -> Vec<Row> {
        let facts = Facts {
            latest_published: Some(chrono::Utc::now()),
            releases_last_year: Some(8),
            licenses: vec!["MIT".into()],
            deprecated: true,
            ..Default::default()
        };
        vec![Row {
            analyzed_version: Some("2.88.2".into()),
            score: score(&facts, chrono::Utc::now()),
            dependency: Dependency {
                name: "request".into(),
                requested: None,
                ecosystem: Ecosystem::Npm,
                direct: true,
            },
            error: None,
        }]
    }

    #[test]
    fn renders_without_a_real_terminal() {
        let app = App::new(sample_rows());
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui::draw(f, &app)).unwrap();

        let buffer = terminal.backend().buffer();
        let text: String = buffer.content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("deprot"), "header missing");
        assert!(text.contains("request"), "package row missing");
        assert!(text.contains("RISKY"), "verdict missing");
    }

    #[test]
    fn q_quits() {
        let mut app = App::new(sample_rows());
        handle_key(&mut app, KeyCode::Char('q'), KeyModifiers::NONE);
        assert!(app.should_quit);
    }

    #[test]
    fn ctrl_c_quits() {
        let mut app = App::new(sample_rows());
        handle_key(&mut app, KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(app.should_quit);
    }
}
