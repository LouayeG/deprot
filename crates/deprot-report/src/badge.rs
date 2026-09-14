//! Grade badge generation. `deprot --badge` emits an embeddable SVG (or a shields.io endpoint JSON
//! with `--json`) reflecting a project's overall grade, for dropping into a README.

/// Badge color for a letter grade (deprot's brand ramp).
fn grade_color(grade: &str) -> &'static str {
    match grade {
        "A" => "#7ee787",
        "B" => "#56d8c2",
        "C" => "#f0be64",
        "D" => "#f0965a",
        _ => "#ff6b6b", // F
    }
}

/// Approximate rendered width (px) of a short label at 11px in the badge font.
fn text_width(s: &str) -> u32 {
    // ~6.5px/char + 20px horizontal padding, rounded.
    (s.chars().count() as u32) * 7 + 20
}

/// A self-contained flat SVG grade badge (label "deprot", message e.g. "A · 94/100").
pub fn grade_badge_svg(grade: &str, value: u8) -> String {
    let label = "deprot";
    let msg = format!("{grade} · {value}/100");
    let color = grade_color(grade);
    let lw = text_width(label);
    let mw = text_width(&msg);
    let total = lw + mw;
    let lx = lw * 5; // centered text x (scaled x10 for crisp positioning)
    let mx = (lw * 10 + mw * 5) as i64;
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" aria-label="deprot: grade {grade} ({value}/100)">
  <title>deprot: grade {grade} ({value}/100)</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{lw}" height="20" fill="#20262e"/>
    <rect x="{lw}" width="{mw}" height="20" fill="{color}"/>
    <rect width="{total}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{lx}" y="150" transform="scale(.1)" fill="#010101" fill-opacity=".3" textLength="{ltl}">{label}</text>
    <text x="{lx}" y="140" transform="scale(.1)" textLength="{ltl}">{label}</text>
    <text x="{mx}" y="150" transform="scale(.1)" fill="#010101" fill-opacity=".3" textLength="{mtl}">{msg}</text>
    <text x="{mx}" y="140" transform="scale(.1)" fill="#04220b" textLength="{mtl}">{msg}</text>
  </g>
</svg>"##,
        ltl = (lw - 20) * 10,
        mtl = (mw - 20) * 10,
    )
}

/// A shields.io endpoint JSON (`schemaVersion` 1) — host it and point shields at it for a
/// live-updating badge.
pub fn grade_badge_endpoint(grade: &str, value: u8) -> String {
    let color = grade_color(grade).trim_start_matches('#');
    format!(
        r#"{{
  "schemaVersion": 1,
  "label": "deprot",
  "message": "{grade} · {value}/100",
  "color": "{color}"
}}"#
    )
}
