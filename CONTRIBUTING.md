# Contributing to deprot

Thanks for your interest in improving deprot! Contributions of all sizes are welcome — new ecosystem
adapters are the easiest and highest-impact place to start.

## Getting set up

```bash
git clone https://github.com/LouayeG/deprot && cd deprot
cargo build
cargo test --workspace
```

deprot requires Rust **1.90+** (the tree-sitter parsing stack sets the floor).

## Before you open a pull request

Please make sure the following pass locally — CI enforces all three:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

New behavior should come with tests. The scoring engine (`deprot-core`) is pure and takes an explicit
clock, so its tests are fully deterministic — keep it that way (no I/O, no ambient time).

## Architecture

deprot is a small Cargo workspace with a strict "pure core, I/O at the edges" split:

- `deprot-manifest` — parse manifests + lockfiles into a dependency graph
- `deprot-collect` — fetch public data (the only crate that touches the network)
- `deprot-core` — turn facts into a deterministic score (pure, zero-I/O)
- `deprot-report` — render tables, JSON, SARIF, SBOM, badges
- the feature crates (`-secrets`, `-actions`, `-hygiene`, `-reach`, `-malware`, `-netmon`, `-policy`,
  `-tui`) and `deprot-cli`, which wires it all together

## Adding an ecosystem

1. Add the variant to `Ecosystem` in `deprot-core` (with its deps.dev/OSV/label mappings).
2. Add a manifest parser in `deprot-manifest` and register it for detection.
3. Update the exhaustive `match`es the compiler points you to.

## Reporting bugs & requesting features

Use the issue templates. For security issues, see [SECURITY.md](SECURITY.md).
