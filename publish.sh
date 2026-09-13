#!/usr/bin/env bash
# Publish the deprot workspace to crates.io in dependency order.
#
# Prerequisites (run once):
#   cargo login <your-crates.io-token>   # from https://crates.io/settings/tokens
#
# Then:
#   ./publish.sh            # publish for real
#   ./publish.sh --dry-run  # validate without uploading
#
# crates must go up in dependency order; `cargo publish` waits for each to appear in the
# index before the next one (which depends on it) is verified.
set -euo pipefail

DRY_RUN=""
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN="--dry-run"
fi

CRATES=(
  deprot-core
  deprot-secrets
  deprot-actions
  deprot-manifest
  deprot-collect
  deprot-report
  deprot-policy
  deprot-tui
  deprot
)

for crate in "${CRATES[@]}"; do
  echo ">>> publishing ${crate} ${DRY_RUN}"
  cargo publish -p "${crate}" ${DRY_RUN}
done

echo "done. try: cargo install deprot"
