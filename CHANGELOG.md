# Changelog

All notable changes to deprot are documented here. This project adheres to
[Semantic Versioning](https://semver.org).

**Stability scope (1.0):** the `deprot` **command-line interface** — its flags, exit codes, and the
shapes of its `--json` / `--sarif` / `--sbom` output — is the stable, semver-governed surface. The
internal library crates (`deprot-core`, `deprot-manifest`, `deprot-collect`, …) are published so the
CLI is installable and are **not** a stable API; they may change in minor releases.

## [1.0.0]

### Added
- **PyPI source manifests**: `requirements.txt` and `pyproject.toml` (PEP 621 and Poetry) are now
  parsed, so a Python project is analyzed from source — not only from an installed environment.
- **Grade badge** (`--badge`): emit an embeddable SVG for the project's overall grade, or a
  shields.io endpoint JSON with `--json`.
- **Typosquat radar across all 8 ecosystems**: bundled popular-name lists added for Ruby, PHP,
  Maven and NuGet.

### Changed
- **Fairer scoring**: a maturity dampener stops a widely-used, complete library that simply hasn't
  shipped lately from being graded as "rotting" on staleness alone. It only ever lifts a score;
  deprecation, an archived repo, and unresolved high/critical advisories still force RISKY.
- **Honest reachability**: `--reach` now reports an explicit `unscanned` verdict for ecosystems
  without a source-import scanner, instead of implying those dependencies were checked.
- Declared the accurate **minimum supported Rust version (1.90)**; `cargo install` no longer fails
  confusingly on older toolchains.

### CI / quality
- CI now builds on a pinned MSRV toolchain and **dogfoods** deprot against its own repository.
- Added a per-ecosystem capability matrix to the documentation.

## [0.7.0]
- AST-aware malicious-code detection (JavaScript/TypeScript/Python).
- Broadened to 8 ecosystems (added Ruby, PHP, Maven, NuGet).
- Runtime network monitoring (`--watch`).

## [0.6.0] and earlier
- Reachability, repository-hygiene scoring, and malicious-code scanning.
- GitHub Actions workflow security auditing.
- Vulnerability-first CVE audit and secret scanning.
- Multi-package / monorepo discovery.
- The initial grading engine, transitive tree + blast radius, policy-as-code, SBOM/SARIF export,
  the interactive TUI, and more.
