# Publishing to crates.io

`deprot` is a workspace of 7 crates. They publish in dependency order (a downstream crate can't be
verified until the crate it depends on is on the index):

```
deprot-core → deprot-manifest → deprot-collect → deprot-report → deprot-policy → deprot-tui → deprot
```

## One-time setup

1. Create a token at https://crates.io/settings/tokens
2. Log in locally:

   ```bash
   cargo login <your-token>
   ```

## Publish

```bash
./publish.sh --dry-run   # validate everything packages & builds, no upload
./publish.sh             # publish for real
```

After it finishes, anyone can install the CLI with:

```bash
cargo install deprot
```

## Notes

- The version for every crate is the single `[workspace.package] version` in the root `Cargo.toml`.
  Bump it there before a release.
- Internal dependencies carry both a `path` and a `version` (in `[workspace.dependencies]`), which is
  what makes them publishable.
- The `deprot` binary crate's crates.io page uses the root `README.md` (linked via its `readme` field).
