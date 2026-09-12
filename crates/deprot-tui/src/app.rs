//! Interactive app state and input handling — deliberately free of any terminal I/O so it can be
//! unit-tested without a real TTY. [`crate::run`] owns the terminal; this owns the logic.

use deprot_core::Tier;
use deprot_report::Row;

/// How the dependency list is ordered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sort {
    /// Worst tier first, then ascending score (the default triage order).
    Tier,
    /// Lowest score first.
    Score,
    /// Alphabetical by package name.
    Name,
}

impl Sort {
    /// Cycle to the next sort mode (wraps).
    fn next(self) -> Sort {
        match self {
            Sort::Tier => Sort::Score,
            Sort::Score => Sort::Name,
            Sort::Name => Sort::Tier,
        }
    }

    /// Short label for the footer/header.
    pub fn label(self) -> &'static str {
        match self {
            Sort::Tier => "tier",
            Sort::Score => "score",
            Sort::Name => "name",
        }
    }
}

/// The full interactive application state.
pub struct App {
    /// All scored rows, held in the current sort order.
    pub rows: Vec<Row>,
    /// Index of the highlighted row.
    pub selected: usize,
    /// Active sort mode.
    pub sort: Sort,
    /// Set when the user has asked to quit.
    pub should_quit: bool,
}

impl App {
    /// Build the app from scored rows, applying the default (tier) sort.
    pub fn new(rows: Vec<Row>) -> Self {
        let mut app = App {
            rows,
            selected: 0,
            sort: Sort::Tier,
            should_quit: false,
        };
        app.apply_sort();
        app
    }

    /// The currently highlighted row, if any.
    pub fn current(&self) -> Option<&Row> {
        self.rows.get(self.selected)
    }

    /// Move the selection down by one, clamped to the last row.
    pub fn next(&mut self) {
        if !self.rows.is_empty() {
            self.selected = (self.selected + 1).min(self.rows.len() - 1);
        }
    }

    /// Move the selection up by one, clamped to the first row.
    pub fn prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// Jump to the first row.
    pub fn first(&mut self) {
        self.selected = 0;
    }

    /// Jump to the last row.
    pub fn last(&mut self) {
        if !self.rows.is_empty() {
            self.selected = self.rows.len() - 1;
        }
    }

    /// Cycle the sort mode, keeping the same package highlighted across the reorder.
    pub fn cycle_sort(&mut self) {
        let keep = self.current().map(|r| r.dependency.name.clone());
        self.sort = self.sort.next();
        self.apply_sort();
        if let Some(name) = keep {
            if let Some(idx) = self.rows.iter().position(|r| r.dependency.name == name) {
                self.selected = idx;
            }
        }
    }

    fn apply_sort(&mut self) {
        match self.sort {
            Sort::Tier => self.rows.sort_by(|a, b| {
                tier_rank(b.score.tier)
                    .cmp(&tier_rank(a.score.tier))
                    .then(a.score.value.cmp(&b.score.value))
            }),
            Sort::Score => self.rows.sort_by_key(|r| r.score.value),
            Sort::Name => self
                .rows
                .sort_by(|a, b| a.dependency.name.cmp(&b.dependency.name)),
        }
        if self.selected >= self.rows.len() {
            self.selected = self.rows.len().saturating_sub(1);
        }
    }

    /// Aggregate counts for the summary line: `(ok, caution, risky)`.
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut c = (0, 0, 0);
        for r in &self.rows {
            match r.score.tier {
                Tier::Ok => c.0 += 1,
                Tier::Caution => c.1 += 1,
                Tier::Risky => c.2 += 1,
            }
        }
        c
    }
}

/// Higher rank = worse = sorts first under `Sort::Tier`.
fn tier_rank(t: Tier) -> u8 {
    match t {
        Tier::Ok => 0,
        Tier::Caution => 1,
        Tier::Risky => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deprot_core::{score, Facts};

    fn row(name: &str, deprecated: bool) -> Row {
        let facts = Facts {
            latest_published: Some(chrono_now()),
            releases_last_year: Some(6),
            licenses: vec!["MIT".into()],
            deprecated,
            ..Default::default()
        };
        Row {
            analyzed_version: Some("1.0.0".into()),
            score: score(&facts, chrono_now()),
            dependency: deprot_core::Dependency {
                name: name.into(),
                requested: None,
                ecosystem: deprot_core::Ecosystem::Npm,
                direct: true,
            },
            error: None,
        }
    }

    fn chrono_now() -> chrono::DateTime<chrono::Utc> {
        use chrono::TimeZone;
        chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    #[test]
    fn default_sort_puts_risky_first() {
        let app = App::new(vec![row("healthy", false), row("bad", true)]);
        assert_eq!(app.rows[0].dependency.name, "bad");
    }

    #[test]
    fn navigation_is_clamped() {
        let mut app = App::new(vec![row("a", false), row("b", false)]);
        app.prev(); // already at top
        assert_eq!(app.selected, 0);
        app.next();
        app.next();
        app.next(); // past the end
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn cycle_sort_keeps_selection_on_same_package() {
        let mut app = App::new(vec![row("zeta", false), row("alpha", true)]);
        // default tier sort: "alpha" (deprecated) first; select "zeta".
        app.selected = app
            .rows
            .iter()
            .position(|r| r.dependency.name == "zeta")
            .unwrap();
        app.cycle_sort(); // -> score
        assert_eq!(app.current().unwrap().dependency.name, "zeta");
    }

    #[test]
    fn counts_add_up() {
        let app = App::new(vec![row("a", false), row("b", true), row("c", false)]);
        let (ok, _caution, risky) = app.counts();
        assert_eq!(ok, 2);
        assert_eq!(risky, 1);
    }
}
