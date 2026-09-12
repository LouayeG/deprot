<div align="center">

# deprot

**Grade your dependencies for rot & supply-chain risk — local, no API keys, no cloud, no signup.**

Point it at any project and get an instant, explainable health report on every dependency:
a **0–100 score**, a **letter grade**, and an **OK / CAUTION / RISKY** verdict — with the reasons.

[![CI](https://github.com/LouayeG/deprot/actions/workflows/ci.yml/badge.svg)](https://github.com/LouayeG/deprot/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

</div>

```text
$ deprot

+------------+---------+-------+-------+---------+------------------------------------+
| PACKAGE    | VERSION | SCORE | GRADE | VERDICT | TOP REASON                         |
+=====================================================================================+
| request    | 2.88.2  |  24   | F     | RISKY   | package is deprecated              |
| left-pad   | 1.3.0   |  27   | F     | RISKY   | package is deprecated              |
| chalk      | 6.0.0   |  79   | B     | CAUTION | 1 release(s) in the last 12 months |
| lodash     | 4.18.1  |  89   | B     | OK      | healthy                            |
| express    | 5.2.1   |  96   | A     | OK      | healthy                            |
| typescript | 7.0.2   |  96   | A     | OK      | healthy                            |
+------------+---------+-------+-------+---------+------------------------------------+

6 dependencies analyzed — 2 risky  1 caution  3 ok
```

---

## Why deprot?

Your `package.json` or `Cargo.toml` is a list of promises made by strangers. Some of those
strangers stopped showing up years ago; some handed the keys to someone new; some shipped a
known vulnerability you never heard about. That is **dependency rot**, and after incidents like
the `xz` backdoor it is nobody's idea of a hypothetical.

Existing answers are mostly cloud SaaS: sign up, connect your repo, upload your dependency graph,
trust a dashboard. deprot takes the opposite stance:

- **Local-first.** It runs on your machine and talks only to public, read-only data APIs. Your
  code and your dependency list never leave your computer.
- **No API keys, ever.** Every data source it uses is free and needs no authentication. There is
  no account and nothing to pay for.
- **Explainable.** Every grade comes with the exact signals that produced it (`--explain`). It is
  never a black-box number you have to take on faith.
- **One static binary.** No runtime, no services, no config file. `cargo install` and go.
- **CI-native.** `--json` for machines, `--fail-on` to gate a pull request, and a ready-made
  GitHub Action.

## Install

```bash
# From source (requires a Rust toolchain)
cargo install --git https://github.com/LouayeG/deprot deprot --locked
```

Or grab a prebuilt binary for your platform from the [Releases](https://github.com/LouayeG/deprot/releases) page.

## Usage

```bash
deprot                      # analyze the manifest in the current directory
deprot path/to/project      # analyze a project directory
deprot ./package.json       # analyze a specific manifest file
deprot --prod-only          # skip dev / peer / build dependencies
deprot --explain lodash     # full signal breakdown for matching package(s)
deprot --json               # stable machine-readable report (for CI / scripting)
deprot --fail-on risky      # exit non-zero if anything is RISKY (or worse)
deprot --refresh            # ignore cached facts and refetch
```

### Supported ecosystems

| Ecosystem  | Manifest        | Status |
|------------|-----------------|--------|
| npm        | `package.json`  | ✅ supported |
| crates.io  | `Cargo.toml`    | ✅ supported |
| PyPI       | `requirements.txt` / `pyproject.toml` | 🚧 planned |

Adding an ecosystem is a matter of implementing one `Manifest` parser — the scoring engine and
data collector are ecosystem-agnostic.

### `--explain`

```text
request 2.88.2  —  score 24/100  grade F  [RISKY]

  Forced RISKY because:
    • package is deprecated

  Signals:
    deprecation      ░░░░░░░░░░    0%  (w4)  deprecated: request has been deprecated ...
    vulnerabilities  █████░░░░░   50%  (w3)  1 known advisory(ies); worst GHSA-... (medium)
    staleness        ░░░░░░░░░░    0%  (w2)  last release 2404 days ago
    cadence          ░░░░░░░░░░    0%  (w1)  0 release(s) in the last 12 months
    scorecard        ███░░░░░░░   34%  (w1.5)  OpenSSF Scorecard overall 3.4/10
    license          ██████████  100%  (w1)  Apache-2.0 (permissive)
```

## How scoring works

Each dependency is reduced to a set of **signals**, each a normalized subscore in `0.0..=1.0`
with a weight. The final **0–100 value** is the weight-normalized average of whatever signals
could be computed (a missing data source lowers confidence rather than unfairly tanking a grade).

| Signal            | Weight | What it measures |
|-------------------|:------:|------------------|
| `deprecation`     |   4    | Registry-level deprecation of the package/version |
| `archived`        |   3    | Upstream source repository is archived (abandoned) |
| `vulnerabilities` |   3    | Known advisories, driven by the worst CVSS severity |
| `staleness`       |   2    | Time since the most recent release (fresh < 90d, decays to ~2y) |
| `scorecard`       |  1.5   | OpenSSF Scorecard — upstream engineering hygiene |
| `bus_factor`      |  1.5   | Contributor concentration / capture risk (needs a GitHub token) |
| `cadence`         |   1    | Releases in the trailing 12 months |
| `license`         |   1    | License present and permissive vs. copyleft vs. missing |

The value maps to a letter grade (**A** ≥ 90, **B** ≥ 75, **C** ≥ 60, **D** ≥ 40, **F** below)
and a verdict tier (**OK** ≥ 80, **CAUTION** ≥ 55, **RISKY** below).

**Forced verdicts.** Some facts are too important to be averaged away. A registry deprecation, an
archived upstream, or an **unresolved high/critical advisory** forces the verdict to **RISKY**
regardless of the numeric score — and `--explain` tells you which one fired.

## Data sources

All free, all public, all read-only. No key required.

| Source | Auth | Used for |
|--------|:----:|----------|
| [deps.dev](https://deps.dev) (Google Open Source Insights) | none | releases, licenses, advisories, linked repo, OpenSSF Scorecard |
| [OSV.dev](https://osv.dev) | none | vulnerability data (via deps.dev advisory records) |
| npm / crates.io / PyPI registries | none | publish metadata |
| GitHub API | optional token | deeper repo signals (bus factor, staleness) — never required |

Results are cached on disk (under your OS cache directory) with a 24h TTL, so re-runs are instant
and friendly to the upstream APIs. Use `--no-cache` or `--refresh` to bypass.

## Use it in CI

Gate pull requests on dependency health with the bundled GitHub Action:

```yaml
# .github/workflows/deps.yml
name: dependency check
on: [pull_request]
jobs:
  deprot:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: LouayeG/deprot@main
        with:
          fail-on: risky   # ok | caution | risky
```

Or call the binary directly and consume the JSON:

```bash
deprot --json > deprot-report.json
deprot --fail-on caution   # non-zero exit fails the job
```

## Architecture

deprot is a small Cargo workspace with a strict "pure core, I/O at the edges" split:

```
deprot-manifest   parse a manifest  ->  Vec<Dependency>
deprot-collect    fetch public data ->  Facts        (the only crate that touches the network)
deprot-core       Facts             ->  Score        (pure, zero-I/O, fully deterministic)
deprot-report     Score             ->  table / JSON / --explain
deprot-cli        wires it together and owns the CLI + exit codes
```

Because `deprot-core` is pure — it takes an explicit reference time and never reaches for a clock,
a socket, or the filesystem — the entire scoring model is unit-testable and replayable from
fixtures. `cargo test --workspace` runs the whole suite offline.

## Building from source

```bash
git clone https://github.com/LouayeG/deprot
cd deprot
cargo build --release        # binary at target/release/deprot
cargo test --workspace       # run the test suite
cargo clippy --workspace --all-targets -- -D warnings
```

## Roadmap

- PyPI (`requirements.txt` / `pyproject.toml`) adapter
- Lockfile-aware analysis (score the exact resolved tree, not just the latest version)
- SARIF output for code-scanning integrations
- Bus-factor signal via the optional GitHub token
- An embeddable per-project grade badge

Contributions welcome — new ecosystems are the easiest place to start.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
