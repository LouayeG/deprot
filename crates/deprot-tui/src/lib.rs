//! # deprot-tui
//!
//! An interactive terminal UI for browsing a deprot analysis: a project-health hero gauge, a
//! navigable dependency list with a live grade-distribution chart, and a detail pane that shows a
//! big block-letter grade plus the animated signal breakdown for the highlighted package.
//!
//! State and rendering live in [`app`] and [`ui`] and are terminal-free; this module owns the
//! crossterm terminal lifecycle, the animation timing, and the input loop.

mod app;
mod theme;
mod ui;

pub use app::{App, Sort};

use deprot_core::{Dependency, Ecosystem};
use deprot_report::Row;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use std::time::{Duration, Instant};

/// How long the startup splash shows before dissolving into the UI (skippable with any key).
const SPLASH_MS: u64 = 1000;
/// Duration of the signal-fill animation after the selection changes.
const ANIM_SECS: f64 = 0.18;

/// Launch the interactive TUI over the given scored rows. Blocks until the user quits, then
/// restores the terminal (even on error/panic, via ratatui's install hooks).
pub fn run(rows: Vec<Row>) -> anyhow::Result<()> {
    let mut app = App::new(rows);
    let mut terminal = ratatui::init();
    let result = (|| {
        splash_phase(&mut terminal)?;
        main_phase(&mut terminal, &mut app)
    })();
    ratatui::restore();
    result
}

/// Show the branded splash, revealing the banner top-down, until it times out or a key is pressed.
fn splash_phase(terminal: &mut ratatui::DefaultTerminal) -> anyhow::Result<()> {
    let start = Instant::now();
    let total = Duration::from_millis(SPLASH_MS);
    loop {
        let elapsed = start.elapsed();
        if elapsed >= total {
            return Ok(());
        }
        let reveal = (elapsed.as_secs_f64() / 0.6).min(1.0);
        terminal.draw(|f| ui::draw_splash(f, reveal))?;
        if event::poll(Duration::from_millis(33))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    return Ok(()); // skip the splash
                }
            }
        }
    }
}

/// The main interactive loop with selection-driven animation.
fn main_phase(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> anyhow::Result<()> {
    let mut sel_gen = app.selection_generation;
    let mut sel_time = Instant::now();

    while !app.should_quit {
        if app.selection_generation != sel_gen {
            sel_gen = app.selection_generation;
            sel_time = Instant::now();
        }
        let anim = (sel_time.elapsed().as_secs_f64() / ANIM_SECS).min(1.0);

        terminal.draw(|f| ui::draw(f, app, anim))?;

        // While the fill animates, poll on a short frame budget so it advances; once settled,
        // block on input so we don't spin the CPU.
        let has_input = if anim < 1.0 {
            event::poll(Duration::from_millis(16))?
        } else {
            true // fall through to a blocking read
        };
        if has_input {
            if anim >= 1.0 {
                if let Event::Key(k) = event::read()? {
                    if k.kind == KeyEventKind::Press {
                        handle_key(app, k.code, k.modifiers);
                    }
                }
            } else if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    handle_key(app, k.code, k.modifiers);
                }
            }
        }
    }
    Ok(())
}

/// Apply one key press to the app state.
fn handle_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    // Ctrl-C always quits.
    if mods.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }
    // The help overlay swallows the next key (any key closes it).
    if app.show_help {
        app.show_help = false;
        return;
    }
    // Search-input mode captures text.
    if app.searching {
        match code {
            KeyCode::Esc => app.cancel_search(),
            KeyCode::Enter => app.commit_search(),
            KeyCode::Backspace => app.pop_query(),
            KeyCode::Char(c) => app.push_query(c),
            _ => {}
        }
        return;
    }
    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Down | KeyCode::Char('j') => app.next(),
        KeyCode::Up | KeyCode::Char('k') => app.prev(),
        KeyCode::Char('g') | KeyCode::Home => app.first(),
        KeyCode::Char('G') | KeyCode::End => app.last(),
        KeyCode::PageDown => {
            for _ in 0..3 {
                app.scroll_detail_down();
            }
        }
        KeyCode::PageUp => {
            for _ in 0..3 {
                app.scroll_detail_up();
            }
        }
        KeyCode::Char('s') => app.cycle_sort(),
        KeyCode::Char('f') => app.cycle_filter(),
        KeyCode::Char('/') => app.start_search(),
        KeyCode::Char('?') => app.toggle_help(),
        KeyCode::Char('o') => {
            if let Some(row) = app.current() {
                open_url(&registry_url(&row.dependency));
            }
        }
        _ => {}
    }
}

/// The registry landing page for a dependency (used by the `o` "open" action).
fn registry_url(dep: &Dependency) -> String {
    match dep.ecosystem {
        Ecosystem::Npm => format!("https://www.npmjs.com/package/{}", dep.name),
        Ecosystem::Cargo => format!("https://crates.io/crates/{}", dep.name),
        Ecosystem::PyPI => format!("https://pypi.org/project/{}/", dep.name),
        Ecosystem::Go => format!("https://pkg.go.dev/{}", dep.name),
        Ecosystem::Ruby => format!("https://rubygems.org/gems/{}", dep.name),
        Ecosystem::Php => format!("https://packagist.org/packages/{}", dep.name),
        Ecosystem::Maven => format!(
            "https://central.sonatype.com/artifact/{}",
            dep.name.replacen(':', "/", 1)
        ),
        Ecosystem::NuGet => format!("https://www.nuget.org/packages/{}", dep.name),
    }
}

/// Best-effort open of a URL in the user's default browser. Failures are silently ignored — this
/// is a convenience action, not a critical path.
fn open_url(url: &str) {
    use std::process::Command;
    #[cfg(target_os = "linux")]
    let _ = Command::new("xdg-open").arg(url).spawn();
    #[cfg(target_os = "macos")]
    let _ = Command::new("open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let _ = Command::new("cmd").args(["/C", "start", "", url]).spawn();
}

/// Render a single main-view frame to plain text at the given size, without a real terminal.
/// Useful for documentation snapshots and previews (colors are dropped, layout is preserved).
pub fn render_to_text(rows: Vec<Row>, width: u16, height: u16) -> String {
    use ratatui::{backend::TestBackend, Terminal};
    let app = App::new(rows);
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
    terminal.draw(|f| ui::draw(f, &app, 1.0)).expect("draw");
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

#[cfg(test)]
mod tests {
    use super::*;
    use deprot_core::{score, Facts};
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
            source: None,
        }]
    }

    #[test]
    fn renders_without_a_real_terminal() {
        let app = App::new(sample_rows());
        let backend = TestBackend::new(110, 34);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui::draw(f, &app, 1.0)).unwrap();

        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("DEPROT"), "hero title missing");
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

    #[test]
    fn slash_enters_search_and_typing_filters() {
        let mut app = App::new(sample_rows());
        handle_key(&mut app, KeyCode::Char('/'), KeyModifiers::NONE);
        assert!(app.searching);
        handle_key(&mut app, KeyCode::Char('z'), KeyModifiers::NONE);
        assert_eq!(app.visible_len(), 0); // no package contains 'z'
        handle_key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(!app.searching);
        assert_eq!(app.visible_len(), 1);
    }

    #[test]
    fn recursive_view_shows_subproject_column() {
        let facts = Facts {
            latest_published: Some(chrono::Utc::now()),
            releases_last_year: Some(8),
            total_versions: Some(10),
            licenses: vec!["MIT".into()],
            ..Default::default()
        };
        let rows = vec![Row {
            analyzed_version: Some("1.0.0".into()),
            score: score(&facts, chrono::Utc::now()),
            dependency: Dependency {
                name: "leftpad".into(),
                requested: None,
                ecosystem: Ecosystem::Npm,
                direct: true,
            },
            error: None,
            source: Some("frontend".into()),
        }];
        let text = render_to_text(rows, 120, 30);
        assert!(
            text.contains("SUBPROJECT"),
            "subproject column header missing"
        );
        assert!(text.contains("frontend"), "subproject label missing");
    }

    #[test]
    fn splash_renders() {
        let backend = TestBackend::new(90, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui::draw_splash(f, 1.0)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("LouayeG"), "credit missing from splash");
    }
}
