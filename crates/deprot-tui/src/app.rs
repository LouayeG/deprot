//! Interactive app state and input handling — deliberately free of any terminal I/O so it can be
//! unit-tested without a real TTY. [`crate::run`] owns the terminal; this owns the logic.
//!
//! The master list [`App::all`] is held sorted; [`App::filtered`] is the set of indices currently
//! visible after the tier filter and the name query, and [`App::selected`] indexes into *that*.

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
    fn next(self) -> Sort {
        match self {
            Sort::Tier => Sort::Score,
            Sort::Score => Sort::Name,
            Sort::Name => Sort::Tier,
        }
    }

    /// Short label for the header.
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
    /// Master list, held in the current sort order.
    all: Vec<Row>,
    /// Indices into `all` that are currently visible (after tier filter + query).
    pub filtered: Vec<usize>,
    /// Index into `filtered` of the highlighted row.
    pub selected: usize,
    /// Active sort mode.
    pub sort: Sort,
    /// Show only rows at or worse than this tier; `None` shows everything.
    pub tier_filter: Option<Tier>,
    /// Case-insensitive name query.
    pub query: String,
    /// Whether we are capturing keystrokes into `query`.
    pub searching: bool,
    /// Whether the help overlay is visible.
    pub show_help: bool,
    /// Vertical scroll offset of the detail pane.
    pub detail_scroll: u16,
    /// Set when the user has asked to quit.
    pub should_quit: bool,
    /// Bumped whenever the highlighted package changes — the render loop watches this to (re)start
    /// the signal-fill animation.
    pub selection_generation: u64,
}

impl App {
    /// Build the app from scored rows, applying the default (tier) sort.
    pub fn new(rows: Vec<Row>) -> Self {
        let mut app = App {
            all: rows,
            filtered: Vec::new(),
            selected: 0,
            sort: Sort::Tier,
            tier_filter: None,
            query: String::new(),
            searching: false,
            show_help: false,
            detail_scroll: 0,
            should_quit: false,
            selection_generation: 0,
        };
        app.apply_sort();
        app
    }

    /// Total number of dependencies (ignoring any filter).
    pub fn total(&self) -> usize {
        self.all.len()
    }

    /// The rows currently visible, in order.
    pub fn visible(&self) -> impl Iterator<Item = &Row> {
        self.filtered.iter().map(move |&i| &self.all[i])
    }

    /// Number of visible rows.
    pub fn visible_len(&self) -> usize {
        self.filtered.len()
    }

    /// The currently highlighted row, if any.
    pub fn current(&self) -> Option<&Row> {
        self.filtered.get(self.selected).map(|&i| &self.all[i])
    }

    /// Project-wide health: the mean of every dependency's score (ignores filtering).
    pub fn overall_score(&self) -> u8 {
        if self.all.is_empty() {
            return 0;
        }
        let sum: u32 = self.all.iter().map(|r| r.score.value as u32).sum();
        (sum / self.all.len() as u32) as u8
    }

    /// Project-wide counts `(ok, caution, risky)` (ignores filtering).
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut c = (0, 0, 0);
        for r in &self.all {
            match r.score.tier {
                Tier::Ok => c.0 += 1,
                Tier::Caution => c.1 += 1,
                Tier::Risky => c.2 += 1,
            }
        }
        c
    }

    // ---- navigation ----

    fn on_selection_changed(&mut self) {
        self.detail_scroll = 0;
        self.selection_generation = self.selection_generation.wrapping_add(1);
    }

    /// Move the selection down by one, clamped to the last visible row.
    pub fn next(&mut self) {
        if !self.filtered.is_empty() {
            let n = (self.selected + 1).min(self.filtered.len() - 1);
            if n != self.selected {
                self.selected = n;
                self.on_selection_changed();
            }
        }
    }

    /// Move the selection up by one, clamped to the first visible row.
    pub fn prev(&mut self) {
        let n = self.selected.saturating_sub(1);
        if n != self.selected {
            self.selected = n;
            self.on_selection_changed();
        }
    }

    /// Jump to the first visible row.
    pub fn first(&mut self) {
        if self.selected != 0 {
            self.selected = 0;
            self.on_selection_changed();
        }
    }

    /// Jump to the last visible row.
    pub fn last(&mut self) {
        if !self.filtered.is_empty() {
            let n = self.filtered.len() - 1;
            if n != self.selected {
                self.selected = n;
                self.on_selection_changed();
            }
        }
    }

    /// Scroll the detail pane.
    pub fn scroll_detail_down(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_add(1);
    }

    /// Scroll the detail pane.
    pub fn scroll_detail_up(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_sub(1);
    }

    // ---- sort & filter ----

    /// Cycle the sort mode, keeping the same package highlighted across the reorder.
    pub fn cycle_sort(&mut self) {
        let keep = self.current().map(|r| r.dependency.name.clone());
        self.sort = self.sort.next();
        self.apply_sort();
        self.restore_selection(keep.clone());
        self.note_selection_change(keep);
    }

    /// Cycle the tier filter: all → risky → caution+worse → all.
    pub fn cycle_filter(&mut self) {
        let keep = self.current().map(|r| r.dependency.name.clone());
        self.tier_filter = match self.tier_filter {
            None => Some(Tier::Risky),
            Some(Tier::Risky) => Some(Tier::Caution),
            _ => None,
        };
        self.rebuild();
        self.restore_selection(keep.clone());
        self.note_selection_change(keep);
    }

    /// Human label for the active filter.
    pub fn filter_label(&self) -> &'static str {
        match self.tier_filter {
            None => "all",
            Some(Tier::Risky) => "risky",
            Some(Tier::Caution) => "caution+",
            Some(Tier::Ok) => "all",
        }
    }

    fn apply_sort(&mut self) {
        match self.sort {
            Sort::Tier => self.all.sort_by(|a, b| {
                tier_rank(b.score.tier)
                    .cmp(&tier_rank(a.score.tier))
                    .then(a.score.value.cmp(&b.score.value))
            }),
            Sort::Score => self.all.sort_by_key(|r| r.score.value),
            Sort::Name => self
                .all
                .sort_by(|a, b| a.dependency.name.cmp(&b.dependency.name)),
        }
        self.rebuild();
    }

    /// Recompute the visible index set from the current filter + query.
    fn rebuild(&mut self) {
        let q = self.query.to_lowercase();
        self.filtered = self
            .all
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                let tier_ok = match self.tier_filter {
                    Some(min) => r.score.tier >= min,
                    None => true,
                };
                let query_ok = q.is_empty() || r.dependency.name.to_lowercase().contains(&q);
                tier_ok && query_ok
            })
            .map(|(i, _)| i)
            .collect();
        if self.selected >= self.filtered.len() {
            self.selected = self.filtered.len().saturating_sub(1);
        }
    }

    fn restore_selection(&mut self, keep: Option<String>) {
        if let Some(name) = keep {
            if let Some(pos) = self
                .filtered
                .iter()
                .position(|&i| self.all[i].dependency.name == name)
            {
                self.selected = pos;
            }
        }
    }

    /// If the highlighted package differs from `prev` (a filter/query/sort implicitly moved the
    /// selection to a different package), reset the detail pane and re-trigger its animation — the
    /// same bookkeeping an explicit navigation does.
    fn note_selection_change(&mut self, prev: Option<String>) {
        let now = self.current().map(|r| r.dependency.name.clone());
        if now != prev {
            self.on_selection_changed();
        }
    }

    // ---- search input ----

    /// Enter search-input mode.
    pub fn start_search(&mut self) {
        self.searching = true;
    }

    /// Leave search-input mode, keeping the current query as the active filter.
    pub fn commit_search(&mut self) {
        self.searching = false;
    }

    /// Leave search-input mode and clear the query.
    pub fn cancel_search(&mut self) {
        let keep = self.current().map(|r| r.dependency.name.clone());
        self.searching = false;
        self.query.clear();
        self.rebuild();
        self.note_selection_change(keep);
    }

    /// Append a character to the query and refilter.
    pub fn push_query(&mut self, c: char) {
        let keep = self.current().map(|r| r.dependency.name.clone());
        self.query.push(c);
        self.rebuild();
        self.note_selection_change(keep);
    }

    /// Delete the last query character and refilter.
    pub fn pop_query(&mut self) {
        let keep = self.current().map(|r| r.dependency.name.clone());
        self.query.pop();
        self.rebuild();
        self.note_selection_change(keep);
    }

    /// Toggle the help overlay.
    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
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
        assert_eq!(app.current().unwrap().dependency.name, "bad");
    }

    #[test]
    fn navigation_is_clamped_and_bumps_generation() {
        let mut app = App::new(vec![row("a", false), row("b", false)]);
        let g0 = app.selection_generation;
        app.prev(); // already at top → no change
        assert_eq!(app.selected, 0);
        assert_eq!(app.selection_generation, g0);
        app.next();
        assert!(app.selection_generation > g0);
        app.next();
        app.next(); // past the end
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn cycle_sort_keeps_selection_on_same_package() {
        let mut app = App::new(vec![row("zeta", false), row("alpha", true)]);
        let pos = app
            .visible()
            .position(|r| r.dependency.name == "zeta")
            .unwrap();
        app.selected = pos;
        app.cycle_sort();
        assert_eq!(app.current().unwrap().dependency.name, "zeta");
    }

    #[test]
    fn tier_filter_hides_healthy() {
        let mut app = App::new(vec![row("a", false), row("bad", true), row("c", false)]);
        app.cycle_filter(); // -> risky only
        assert_eq!(app.visible_len(), 1);
        assert_eq!(app.current().unwrap().dependency.name, "bad");
    }

    #[test]
    fn query_filters_by_name() {
        let mut app = App::new(vec![row("react", false), row("lodash", false)]);
        app.start_search();
        app.push_query('l');
        assert_eq!(app.visible_len(), 1);
        assert_eq!(app.current().unwrap().dependency.name, "lodash");
        app.cancel_search();
        assert_eq!(app.visible_len(), 2);
    }

    #[test]
    fn filtering_that_moves_selection_resets_detail() {
        let mut app = App::new(vec![row("a", false), row("bad", true), row("c", false)]);
        // Highlight a healthy row and scroll its detail pane.
        app.next();
        assert_ne!(app.current().unwrap().dependency.name, "bad");
        app.scroll_detail_down();
        assert!(app.detail_scroll > 0);
        let gen = app.selection_generation;

        // Filtering to risky-only drops the healthy selection, moving the highlight to "bad".
        app.cycle_filter();
        assert_eq!(app.current().unwrap().dependency.name, "bad");
        assert_eq!(
            app.detail_scroll, 0,
            "detail scroll must reset on selection change"
        );
        assert!(app.selection_generation > gen, "animation must re-trigger");
    }

    #[test]
    fn overall_and_counts_ignore_filter() {
        let mut app = App::new(vec![row("a", false), row("bad", true)]);
        app.cycle_filter(); // filter to risky
        assert_eq!(app.total(), 2);
        let (_ok, _c, risky) = app.counts();
        assert_eq!(risky, 1);
        assert!(app.overall_score() > 0);
    }
}
