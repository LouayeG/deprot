//! Visual identity for the TUI: one signature accent, reserved status colors, recessive chrome,
//! and the block-art used by the splash banner and the big per-package grade. Keeping every color
//! and glyph decision here is what lets the rest of the UI stay quiet so the data pops.

use deprot_core::{Grade, Tier};
use ratatui::style::Color;

/// Signature accent — a bright, healthy green. Used for branding (title, gauges at their best).
pub const ACCENT: Color = Color::Rgb(126, 231, 135);
/// Recessive chrome (borders, secondary labels).
pub const DIM: Color = Color::DarkGray;
/// Muted ink for body text that isn't carrying status.
pub const INK: Color = Color::Gray;

/// Status color for a verdict tier (reserved — never reused for anything non-status).
pub fn tier_color(tier: Tier) -> Color {
    match tier {
        Tier::Ok => Color::Rgb(126, 231, 135),      // green
        Tier::Caution => Color::Rgb(240, 190, 100), // amber
        Tier::Risky => Color::Rgb(255, 107, 107),   // coral
    }
}

/// Status color for a letter grade — an ordered good→bad ramp.
pub fn grade_color(grade: Grade) -> Color {
    match grade {
        Grade::A => Color::Rgb(126, 231, 135), // green
        Grade::B => Color::Rgb(86, 216, 194),  // teal
        Grade::C => Color::Rgb(240, 190, 100), // amber
        Grade::D => Color::Rgb(240, 150, 90),  // orange
        Grade::F => Color::Rgb(255, 107, 107), // coral
    }
}

/// A health fraction (0.0–1.0) colored on the same status ramp — for gauges and signal bars.
pub fn health_color(fraction: f64) -> Color {
    if fraction >= 0.8 {
        Color::Rgb(126, 231, 135)
    } else if fraction >= 0.55 {
        Color::Rgb(86, 216, 194)
    } else if fraction >= 0.4 {
        Color::Rgb(240, 190, 100)
    } else {
        Color::Rgb(255, 107, 107)
    }
}

/// The startup splash banner: "DEPROT" in ANSI-Shadow block letters (6 rows).
pub const BANNER: [&str; 6] = [
    "██████╗  ███████╗ ██████╗  ██████╗   ██████╗  ████████╗",
    "██╔══██╗ ██╔════╝ ██╔══██╗ ██╔══██╗ ██╔═══██╗ ╚══██╔══╝",
    "██║  ██║ █████╗   ██████╔╝ ██████╔╝ ██║   ██║    ██║   ",
    "██║  ██║ ██╔══╝   ██╔═══╝  ██╔══██╗ ██║   ██║    ██║   ",
    "██████╔╝ ███████╗ ██║      ██║  ██║ ╚██████╔╝    ██║   ",
    "╚═════╝  ╚══════╝ ╚═╝      ╚═╝  ╚═╝  ╚═════╝     ╚═╝   ",
];

/// Credit line shown under the banner.
pub const CREDIT: &str = "made by LouayeG";

/// One-line tagline shown under the credit on the splash.
pub const TAGLINE: &str = "dependency rot & supply-chain risk — local, no keys, no cloud";

/// Big 6-row block art for a single letter grade, used as the hero of the detail pane.
pub fn grade_block(grade: Grade) -> [&'static str; 6] {
    match grade {
        Grade::A => [
            " █████╗ ",
            "██╔══██╗",
            "███████║",
            "██╔══██║",
            "██║  ██║",
            "╚═╝  ╚═╝",
        ],
        Grade::B => [
            "██████╗ ",
            "██╔══██╗",
            "██████╔╝",
            "██╔══██╗",
            "██████╔╝",
            "╚═════╝ ",
        ],
        Grade::C => [
            " ██████╗",
            "██╔════╝",
            "██║     ",
            "██║     ",
            "╚██████╗",
            " ╚═════╝",
        ],
        Grade::D => [
            "██████╗ ",
            "██╔══██╗",
            "██║  ██║",
            "██║  ██║",
            "██████╔╝",
            "╚═════╝ ",
        ],
        Grade::F => [
            "███████╗",
            "██╔════╝",
            "█████╗  ",
            "██╔══╝  ",
            "██║     ",
            "╚═╝     ",
        ],
    }
}
