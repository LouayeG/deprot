<div align="center">

<img src="https://raw.githubusercontent.com/LouayeG/deprot/main/assets/logo.png" alt="deprot" width="620">

### Your dependencies are rotting. `deprot` tells you which ones. 🦀🧟

**A local-first supply-chain risk scanner that grades every dependency A→F — no API keys, no cloud, no signup.**

[![crates.io](https://img.shields.io/crates/v/deprot?logo=rust&color=fc8d62)](https://crates.io/crates/deprot)
[![docs.rs](https://img.shields.io/docsrs/deprot-core?logo=docs.rs&label=docs.rs)](https://docs.rs/deprot-core)
[![downloads](https://img.shields.io/crates/d/deprot?color=orange)](https://crates.io/crates/deprot)
[![CI](https://github.com/LouayeG/deprot/actions/workflows/ci.yml/badge.svg)](https://github.com/LouayeG/deprot/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

</div>

---

## The pitch, in one breath

Your `package.json` / `Cargo.toml` is a pile of promises made by strangers on the internet. Some of
those strangers wandered off years ago. Some quietly handed their keys to someone new. Some shipped a
vulnerability you've never heard of. That slow decay is **dependency rot**, and `deprot` is the smoke
detector.

Point it at a project and it hands back a **report card**: a `0–100` score, a letter **grade**, and an
**OK / CAUTION / RISKY** verdict for every dependency — and, crucially, *the reasons why*.

```text
$ deprot

+------------+---------+-------+-------+---------+------------------------------------+
| PACKAGE    | VERSION | SCORE | GRADE | VERDICT | TOP REASON                         |
+=====================================================================================+
| request    | 2.88.2  |  24   | F     | RISKY   | package is deprecated              |
| left-pad   | 1.3.0   |  27   | F     | RISKY   | package is deprecated              |
| chalk      | 6.0.0   |  79   | B     | CAUTION | 1 release in the last 12 months    |
| lodash     | 4.18.1  |  89   | B     | OK      | healthy                            |
| express    | 5.2.1   |  96   | A     | OK      | healthy                            |
| typescript | 7.0.2   |  96   | A     | OK      | healthy                            |
+------------+---------+-------+-------+---------+------------------------------------+

6 dependencies analyzed — 2 risky  1 caution  3 ok
```

No account. No dashboard. No "connect your repo." Your code never leaves your machine — `deprot` only
makes read-only calls to free, public data APIs.

## Install

```bash
cargo install deprot
```

<sub>Published on **[crates.io](https://crates.io/crates/deprot)**. Prefer a binary? Grab one from
[Releases](https://github.com/LouayeG/deprot/releases). Building from source needs **Rust 1.90+**.</sub>

## 60-second tour

```bash
deprot                      # grade the project in the current directory
deprot ./package.json       # or a specific manifest
deprot --recursive          # monorepo? grade every subproject across all 8 ecosystems
deprot --vulns              # vuln-first: every CVE, its severity, and the fix version
deprot --secrets            # scan your own source for leaked API keys / tokens / private keys
deprot --workflows          # audit .github/workflows for CI supply-chain risks
deprot --hygiene            # score the repo's security posture (0–100)
deprot --reach              # which deps are actually imported? (find unused ones)
deprot --malware            # AST-aware scan for dropper / malicious-code signatures
deprot --watch -- npm ci    # run an install/build & flag every outbound connection it makes
deprot --badge > badge.svg  # an embeddable grade badge for your README
deprot --explain lodash     # why did this get that grade? (full breakdown)
deprot --tui                # explore it all in a slick terminal UI
deprot --fail-on risky      # exit non-zero for CI — fail the build on RISKY
```

## The report card 🎓

Every dependency gets a **0–100** score → a letter **grade** → a **verdict**:

| Grade | Score | Vibe |
|:-----:|:-----:|------|
| **A** | 90–100 | fresh, loved, well-run 🌱 |
| **B** | 75–89  | perfectly fine 👍 |
| **C** | 60–74  | keep half an eye on it 👀 |
| **D** | 40–59  | starting to smell 🧀 |
| **F** | < 40   | actively rotting 🧟 |

Some things are too important to average away — a **deprecation**, an **archived** repo, or an
**unresolved high/critical CVE** slam the verdict straight to **RISKY**, and `--explain` tells you
exactly which gremlin did it.

## The interactive TUI 🖥️

`deprot --tui` opens a keyboard-driven dashboard: a **project-health gauge** up top, a navigable list
paired with a **grade-distribution chart**, and a detail pane with a **giant letter grade** + animated
signal bars for whatever you've selected. It even greets you with a splash. 😎

<div align="center">
<img src="https://raw.githubusercontent.com/LouayeG/deprot/main/assets/preview.png" alt="deprot TUI — the interactive dashboard" width="900">
</div>

<sub>Keys: `↑/↓` move · `/` search · `f` filter · `s` sort · `?` help · `q` quit</sub>

## The party tricks 🎩

The stuff cloud tools don't do locally — all free, all keyless:

- 🌳 **`--tree` — see the whole iceberg.** Resolves your *entire* dependency tree from the lockfile,
  scores every package at its exact locked version, and shows each one's **blast radius** (how many of
  your packages it puts at risk). Then it names the single **highest-leverage fix**.
- ☣️ **`--malware` — catch code that shouldn't be there, with a real parser.** For JS/TS/Python it
  parses the source with **tree-sitter** and confirms the dropper pattern *structurally*: an
  **`eval`/`exec` on a decoded or concatenated payload** is flagged even when it's spread across
  newlines or built by string-concat — and, crucially, it is **not** flagged when the scary-looking
  text only appears inside a string or comment (the classic regex false positive). Every finding is
  tagged `AST` (parser-confirmed) or `regex` (heuristic). The regex layer still covers **reverse
  shells** (`/dev/tcp`, `nc -e`, `bash -i`), **`curl | sh`**, **cloud-metadata (IMDS) probes**
  (`169.254.169.254`), **credential-file access** (`~/.aws/credentials`, SSH keys, `.npmrc`, browser
  stores), heavy **obfuscation**, and **history tampering**. `--json` / `--sarif`; fails CI on a
  high/critical hit.
- 📡 **`--watch` — see what an install actually does.** `deprot --watch -- npm install` runs the
  command and **monitors every outbound connection its process tree makes**, in real time, from
  `/proc` — no root, no packet capture. A compromised `postinstall` that phones home, an **IMDS
  credential probe** (`169.254.169.254`), or any connection to a public host stands out immediately;
  loopback/LAN is ignored. `--json` for CI; exits non-zero on a metadata/external connection. This is
  a *dynamic* check nobody expects from a "rot" tool — and that Snyk/Socket/Dependabot don't do
  locally. (Linux.)
- 🎯 **`--reach` — is the risky dependency even used?** Scans your source imports and classifies each
  dependency as **used** (with the file it's imported in), **unused** (a runtime dep never imported —
  a removal candidate and needless attack surface), or **dev**. Finer than a runtime-vs-build split,
  and it cuts alert fatigue: prioritize the risky deps you actually import. npm / Cargo / Go.
- 🧰 **`--hygiene` — score your repo's security posture.** A keyless, local mini-Scorecard: security
  policy, a committed lockfile (per ecosystem), a `.gitignore` that actually covers secrets, **no
  committed credential files** (tracked-only via `git ls-files`, `.example` templates allowed),
  automated dependency updates, CI, and CODEOWNERS — weighted into a **0–100 grade** with per-gap
  remediation. Fails CI only on a serious gap (e.g. a committed credential), not routine nits.
- ⚙️ **`--workflows` — lock down your CI.** Audits `.github/workflows` for the current GitHub Actions
  supply-chain attacks: **template injection** (untrusted `${{ github.event.* }}` in `run:`),
  **pwn-requests** (`pull_request_target`/`workflow_run` checking out untrusted PR code with secrets),
  **unpinned/mutable action refs** (not a commit SHA; `@main` is worst), **`write-all` / missing
  permissions**, and `curl | bash`. `--json` and `--sarif` (per-line code-scanning alerts).
- 🔑 **`--secrets` — catch leaked credentials before they ship.** Scans your *own* source for
  hardcoded API keys, tokens, and private keys with high-precision format rules **plus entropy
  analysis**, and aggressive false-positive suppression (placeholders, `${ENV}` refs, doc/example
  keys, `node_modules`). Every match is **redacted** in output; inline `deprot:allow-secret` suppresses
  a line. `--json` for CI, `--sarif` for per-line GitHub code-scanning alerts.
- 🛡️ **`--vulns` — vuln-first CVE audit.** Every known advisory across your resolved tree, worst-first:
  **CVE id, CVSS, and the exact version to upgrade to.** Vulnerability data is **OSV.dev merged with
  GitHub/deps.dev advisories** (a superset of either alone), with CVSS scored from the raw vector.
  `--json` for CI, `--sarif` for per-CVE GitHub code-scanning alerts; exits non-zero if anything's found.
- 🗂️ **`--recursive` — monorepo mode.** One repo, many subprojects: a `frontend/` (`package.json`), a
  `backend/` (`go.mod`), `packages/*` (`Cargo.toml`)… deprot discovers **every** manifest under the
  directory, grades each in its own section, and fails CI on the worst verdict across all of them.
  Dependency/build dirs (`node_modules`, `vendor`, `target`, …) are skipped. Point deprot at the repo
  root and it just works — no more empty-root dead ends.
- 📦 **`--installed` — grade what's *actually on disk*.** Scans the real install — your `node_modules`
  and the active Python environment (`importlib.metadata`, no lockfile needed) — at the exact versions
  present, so it catches **drift from the lockfile** and packages installed by hand. Add **`--global`**
  to audit machine-wide tooling (`npm root -g`, `pipx`). Runs through the same blast-radius / `--fix` /
  `--fail-on` pipeline as `--tree`.
- 🧬 **`--deep` — the xz check.** Flags when **one maintainer controls a scary share** of your supply
  chain, and which packages **run code on install**.
- 🩹 **`--tree --fix` — a to-do list, not just bad news.** Computes the exact upgrades that raise your
  grades, most impactful first, with the command to run.
- 🕵️ **typosquat radar.** Spots dependencies that are 1–2 keystrokes from a popular package
  (`lodahs`, `expres`) — a classic attack, caught offline.
- 🔀 **`--diff base.lock` — PR mode.** "This change adds 3 deps, 1 RISKY, and moves project health −8."
- ⏳ **`--history express` — a time machine.** A package's release cadence over the years, its longest
  quiet spell, and how stale it is now.
- 📜 **policy-as-code** (`.deprot.toml`): enforce a team standard with **time-boxed waivers**.
- 🔌 **`--sarif` / `--sbom`**: SARIF for GitHub code scanning, CycloneDX SBOM with risk baked in.
- ✈️ **`--offline`**: fully air-gapped — warm the cache once, then zero network.

## How the grade is computed

Each dependency is reduced to a set of **signals**, each a `0.0–1.0` subscore with a weight; the final
number is their weighted average (a missing data source lowers confidence, it doesn't nuke the grade).

| Signal            | Weight | Measures |
|-------------------|:------:|----------|
| `deprecation`     |   4    | Registry-level deprecation |
| `archived`        |   3    | Upstream repo is archived (abandoned) |
| `vulnerabilities` |   3    | Known advisories (worst CVSS wins) |
| `staleness`       |   2    | Time since the last release |
| `scorecard`       |  1.5   | OpenSSF Scorecard (engineering hygiene) |
| `bus_factor`      |  1.5   | Contributor concentration |
| `cadence`         |   1    | Releases in the last 12 months |
| `license`         |   1    | Present & permissive vs. copyleft vs. missing |

## Where the data comes from (spoiler: no keys)

| Source | Auth | Gives us |
|--------|:----:|----------|
| [deps.dev](https://deps.dev) | none | releases, licenses, advisories, linked repo, OpenSSF Scorecard |
| [OSV.dev](https://osv.dev) | none | vulnerabilities — CVE aliases, CVSS vectors, fixed versions (merged with deps.dev/GitHub advisories) |
| npm / crates.io / PyPI / Go / RubyGems / Maven / NuGet | none | publish metadata, maintainers/owners, install scripts |
| GitHub API | *optional* token | deeper repo signals — never required |

**Ecosystems (8):** npm, crates.io, PyPI, Go, RubyGems, Packagist (PHP), Maven, and NuGet — parsed
from their manifests (`package.json`, `Cargo.toml`, `go.mod`, `requirements.txt`/`pyproject.toml`,
`Gemfile`, `composer.json`, `pom.xml`, `*.csproj`/`packages.config`) and, where present, their
lockfiles for exact versions. deps.dev doesn't index Packagist, so PHP vulnerabilities come straight
from OSV.

### What works where

Grading, vulnerabilities, typosquat, tree/blast-radius and SBOM/SARIF span all eight ecosystems.
A few source-analysis features depend on a per-ecosystem scanner that isn't wired everywhere yet —
deprot tells you honestly rather than pretending (e.g. `--reach` reports `unscanned` where it has no
importer). Current coverage:

| Ecosystem | Grade & vulns | Lockfile tree | `--reach` | `--deep` maintainers |
|-----------|:---:|:---:|:---:|:---:|
| npm       | ✓ | ✓ | ✓ | ✓ |
| crates.io | ✓ | ✓ | ✓ | ✓ |
| Go        | ✓ | — | ✓ | — |
| PyPI      | ✓ | via `--installed` | — | — |
| RubyGems  | ✓ | ✓ | — | — |
| Packagist | ✓ (OSV) | ✓ | — | — |
| Maven     | ✓ | — | — | — |
| NuGet     | ✓ | — | — | — |

Results are cached on disk (24h TTL) so re-runs are instant and polite to the APIs.

## Policy as code

Drop a `.deprot.toml` in your repo and `deprot` becomes an enforceable standard that fails CI:

```toml
# .deprot.toml
min_score = 60
max_age_days = 730
required_scorecard = 4.0

[licenses]
deny = ["GPL-3.0", "AGPL-3.0"]

[packages]
deny = ["request", "left-pad"]

[[waivers]]
package = "lodash"
reason  = "risk accepted for Q1; migration tracked in JIRA-123"
until   = "2026-06-01"   # expires — no permanent rug-sweeping
```

## Use it in CI

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
          fail-on: risky
```

## How it's built 🧱

A small Cargo workspace with a strict "pure core, I/O at the edges" split — so the whole scoring engine
is deterministic and testable with **zero network**:

```
deprot-manifest   parse manifests + lockfiles  ->  Dependency / DepGraph
deprot-collect    fetch public data            ->  Facts      (the only crate that hits the network)
deprot-core       Facts                         ->  Score      (pure, zero-I/O, fully deterministic)
deprot-report     Score                         ->  table / JSON / SARIF / SBOM / --tree
deprot-policy     Facts + Score                 ->  policy violations (.deprot.toml)
deprot-tui        Score                         ->  interactive ratatui browser (--tui)
deprot-cli        wires it all together + owns the CLI
```

```bash
git clone https://github.com/LouayeG/deprot && cd deprot
cargo build --release      # → target/release/deprot
cargo test --workspace     # the whole suite runs offline
```

## Roadmap

Deep tarball capability scanning · bundled offline OSV mirror · SBOM ingest · a grade badge you can
embed in your own README · maintainer/typosquat data for the newer ecosystems · `--watch` on macOS.
PRs welcome — new ecosystems are the easiest place to start.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), your choice.

<div align="center"><sub>made with 🦀 and mild paranoia by <b>LouayeG</b></sub></div>
