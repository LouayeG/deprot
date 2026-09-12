# deprot — dependency rot & supply-chain health analyzer

> Working name: **`deprot`** (dependency rot). Swappable — alternates: `bitrot`, `patina`, `moss`, `deptrust`.
> One-liner: **"Point it at any repo and get an instant health + supply-chain risk report on every dependency — no paid API keys, no cloud, no signup."**

---

## 0. Why this project (the thesis)

The engine is architecturally identical to a memecoin "rug check": **ingest public data → compute risk
signals → emit a verdict.** We are pointing that same proven pattern at software dependencies instead of
tokens. This:

- reuses a scoring/clustering engine pattern the author has already shipped and tested,
- targets a *huge, anxious* audience (every dev has a dependency manifest; supply-chain security is a
  front-of-mind topic post-`xz`),
- requires **zero paid API keys** — all data sources below are free and mostly need no auth at all,
- reframes the author's crypto work as transferable **supply-chain risk engineering** (great for hiring).

The goal is **GitHub stars**: a single fast binary, zero config, a "whoa" in 60 seconds, and a README GIF
that sells it in one loop.

---

## 1. Product in one sentence

`cd my-project && deprot` → a color-coded, per-dependency **health score (0–100) + letter grade (A–F) +
risk tier (OK / CAUTION / RISKY)**, plus a repo-level summary and the *reasons* behind each grade.

### Core UX (the 60-second demo)
```
$ deprot                      # auto-detects manifest in cwd
$ deprot ./package.json       # explicit target
$ deprot --json               # machine output for CI
$ deprot --fail-on risky      # non-zero exit → CI gate
$ deprot --explain lodash     # full signal breakdown for one dependency
```

Terminal output = a dense, sorted table (worst offenders first) + a one-line verdict banner. This is the
screenshot that goes on Hacker News and LinkedIn.

---

## 2. Hard constraints (non-negotiable)

1. **No paid API keys, ever.** Anthropic/OpenAI/etc. are explicitly out of scope. No LLM in the pipeline.
2. **Works with zero configuration and zero auth** out of the box (degraded but useful). A *free,
   self-provided* GitHub token is optional and only unlocks deeper repo signals + higher rate limits.
3. **Local-first.** No account, no telemetry, no data leaves the machine except read-only calls to the
   public data sources in §4. Results cached on disk.
4. **Single static binary.** `cargo install deprot` or a downloaded release binary — nothing else.
5. **Deterministic core.** The scoring engine is pure (zero I/O): given the same collected facts it always
   produces the same verdict, so it is fully unit-testable and replayable from cached fixtures.

---

## 3. Architecture (Cargo workspace)

Mirrors the "pure core, I/O at the edges, everything replayable" design.

```
deprot/
├─ crates/
│  ├─ deprot-core        # PURE, zero-I/O. Types (Dependency, Facts, Signal, Score, Verdict) +
│  │                     #   the scoring model. 100% unit-testable from fixtures.
│  ├─ deprot-manifest    # Ecosystem manifest parsers behind a `Manifest` trait.
│  │                     #   Adapters: npm (package.json + lockfile), crates (Cargo.toml/.lock),
│  │                     #   pypi (requirements.txt / pyproject). Emits a normalized dep list.
│  ├─ deprot-collect     # I/O layer. `Collector` trait + adapters that fetch Facts from §4 sources.
│  │                     #   Async (tokio + reqwest, rustls). Bounded concurrency + on-disk cache.
│  ├─ deprot-report      # Renders Score/Verdict → terminal table, JSON, SARIF, Markdown.
│  └─ deprot-cli         # clap-based binary. Wires manifest → collect → core → report.
│  └─ (deprot-tui)       # LATER: ratatui interactive dashboard. Not in MVP.
└─ SPEC.md / README.md / CONSTRAINTS.md
```

**Data flow:** `manifest` (what deps exist) → `collect` (gather Facts per dep, cached, concurrent) →
`core` (pure: Facts → Signals → Score → Verdict) → `report` (render).

**Key trait boundaries** so the tool is ecosystem- and source-agnostic from day one:
- `trait Manifest { fn parse(path) -> Vec<Dependency>; }`
- `trait Collector { async fn collect(&self, dep) -> Facts; }`
- Scoring in `core` operates only on `Facts` — it never knows which ecosystem or source produced them.

---

## 4. Data sources (all free, no paid keys)

| Source | Auth | What it gives us |
|---|---|---|
| **deps.dev** (Google Open Source Insights API) | **none** | Aggregated dependency graph, versions, licenses, advisories, OpenSSF Scorecard, project links. The workhorse — covers npm/crates/pypi/go/maven. |
| **OSV.dev** | **none** | Known vulnerabilities per package+version. Free bulk + query API. |
| **npm registry** (`registry.npmjs.org`) | none | Publish dates, version cadence, deprecation flags, maintainer list. |
| **crates.io API** | none | Same for Rust crates. |
| **PyPI JSON API** | none | Same for Python. |
| **GitHub REST/GraphQL** | **optional free token** | Deep repo signals: last commit, issue response time, archived/deprecated, contributor concentration (bus factor), star trend. Unauth works but rate-limited (60/hr); a free personal token → 5000/hr. Never required. |
| **OpenSSF Scorecard** | none (via deps.dev) | Best-practices score (branch protection, CI, signed releases, etc.). |

> Note on "scraping": we prefer the JSON APIs above (stable, polite, rate-limit-friendly) over HTML
> scraping. Where a repo has no registry presence we fall back to the GitHub API. All read-only.

---

## 5. The signals (what "rot" means)

Each dependency is scored on weighted signals. All derived from §4 Facts; all computed in the pure core.

**Maintenance health**
- Days since last release / last commit (staleness curve).
- Release cadence trend (slowing down → rot).
- `deprecated` / `archived` flags → hard penalties.

**Supply-chain / capture risk** *(this is the DBSCAN/identity-clustering muscle, aimed at authorship)*
- **Bus factor**: contributor concentration. A dep where 1 author owns >90% of commits is fragile.
- Sudden new-maintainer + immediate release pattern (the classic takeover signal).
- Number of active maintainers vs. downloads (popularity/maintenance mismatch = risk).

**Security**
- Open known vulnerabilities (OSV) weighted by severity, and whether a fixed version exists.
- OpenSSF Scorecard score (signed releases, branch protection, CI, dangerous workflows).

**Hygiene**
- License present + permissive/known vs. missing/unknown.
- Deep/duplicate transitive tree bloat (optional, later).

### Scoring model
- Each signal → normalized 0–1 subscore with an explicit weight (weights live in one table in `core`,
  documented and tunable).
- Aggregate → **health score 0–100** → **letter grade A–F** → **risk tier** (OK ≥ threshold,
  CAUTION mid, RISKY low **or** any unfixed high-severity vuln / archived / deprecated → forced RISKY).
- Every verdict carries the list of contributing reasons → powers `--explain`. **Explainability is the
  feature**: never a black-box number.

---

## 6. Ecosystem rollout

- **MVP ships npm first** — largest audience, most supply-chain drama → most stars.
- **crates.io second** — lets the author dogfood on their own Rust repos.
- **PyPI third.** Architecture (the `Manifest` trait) makes each new ecosystem an adapter, not a rewrite.

---

## 7. Tech stack

- Rust, `tokio` async, `reqwest` + **rustls** (no native-tls headaches), `clap` v4 (derive), `serde`,
  `comfy-table` (or hand-rolled) for the table, `owo-colors` for grades.
- On-disk cache under the OS cache dir (`directories` crate), TTL'd, so re-runs are instant and
  rate-limit-friendly. `--no-cache` / `--refresh` flags.
- `criterion` benches on the pure core. Property tests (`proptest`) on the scoring math.
- CI (GitHub Actions): fmt + clippy `-D warnings` + test matrix + release-binary build (macOS/Linux/Windows).

---

## 8. Milestones (each is a shippable increment)

- **M0 — skeleton**: workspace, crates, CI, `deprot --version`. (head-start target)
- **M1 — walking skeleton**: parse `package.json` → for each dep hit deps.dev + OSV → print a table with
  a real (even if crude) score. *This is the first demoable moment.*
- **M2 — the scoring engine**: full weighted signal model in `core`, `--explain`, letter grades, cache.
- **M3 — CI-grade**: `--json`, `--sarif`, `--fail-on <tier>`, lockfile-aware (analyze the resolved tree).
- **M4 — depth**: GitHub deep signals (bus factor, staleness) behind optional token; crates.io adapter.
- **M5 — polish for launch**: README + GIF (asciinema/vhs), `cargo install`, prebuilt release binaries,
  GitHub Action wrapper so people can drop it in their CI.
- **M6 — TUI** (optional, post-launch): ratatui interactive drill-down.

---

## 9. Star / launch strategy (this is a goal, so it's in the spec)

- README opens with the GIF + the one-liner + a `cargo install` line. Value before scrolling.
- A **grade badge** users can embed in their own READMEs (`![deprot](…A)`) → organic distribution.
- A **GitHub Action** so repos gate PRs on `deprot --fail-on risky` → sticky adoption.
- Launch post framing: *"I built a supply-chain risk engine that grades your dependencies in seconds —
  local, no keys, no cloud."* Lead with the xz/supply-chain anxiety angle.
- Comparison table vs. cloud SaaS (Snyk/Socket): local-first, free, zero-signup, single binary.

---

## 10. Open decisions (locked defaults, override anytime)

- Name: `deprot` (default). → change before M0 if you have a preference.
- License: MIT/Apache-2.0 dual (Rust-ecosystem norm). 
- First ecosystem: **npm** (locked for stars; crates a close dogfood second).
- GitHub token: optional, read from `GITHUB_TOKEN` env; tool loudly works without it.

---

## 11. What I need from you at head-start
Nothing blocking. Optionally: a preferred final name, and whether to target npm (default) or crates first.
No keys required to build M0–M3. A *free* GitHub token only helps at M4 and you supply it to your own
shell — never to me or the tool.
