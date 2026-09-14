# Security Policy

## Reporting a vulnerability

If you discover a security issue in deprot, please report it privately rather than opening a public
issue:

- Use GitHub's **[Report a vulnerability](https://github.com/LouayeG/deprot/security/advisories/new)**
  (Security → Advisories) to open a private advisory, **or**
- email the maintainer at the address on the GitHub profile.

Please include steps to reproduce and, if possible, a minimal example. We aim to acknowledge reports
within a few days and to ship a fix promptly for confirmed issues.

## Scope

deprot runs locally and makes only read-only requests to public data APIs; it requires no
credentials. Reports of particular interest include: a crafted manifest, lockfile, or source file
that causes a panic or hang, any path-traversal or unexpected write, or a way for scanned content to
exfiltrate data.

## Supported versions

Security fixes target the latest released version.
