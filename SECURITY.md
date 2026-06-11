# Security Policy

## Reporting a Vulnerability

Found a security issue? **Don't open a public issue.**

Email **security@depcheck.dev** (or DM a maintainer on GitHub) with:
- What you found
- How to reproduce it
- Potential impact

We'll acknowledge within 48 hours and keep you updated.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | ✅ Yes |
| Older releases | ❌ No |

Security fixes go to `main` and get released ASAP.

## What We Consider Security Issues

- Vulnerability data manipulation (OSV.dev response parsing)
- Path traversal in file scanning/export
- SBOM injection via malicious package metadata
- License classification bypass
- Dependency confusion via PyPI API responses

## What We Don't Consider Security Issues

- Bugs requiring local filesystem access you already have
- Denial-of-service via massive dependency trees
- Issues in optional visualization deps (D3.js in generated HTML)

## Disclosure Timeline

1. **Day 0**: Private report
2. **Day 1-2**: Triage + confirm
3. **Day 7-30**: Fix + test
4. **Day 30+**: Public disclosure, release, credit (unless you want anonymity)

## Security Practices

- Minimal dependencies — all well-maintained, popular packages
- `pip-audit` runs in CI on every PR
- No `eval()`, `exec()`, `pickle.load()` on untrusted input
- HTTP calls use `httpx` with timeouts and validation
- File operations use `pathlib` with validation
- SBOM export validates all data before writing

Run locally:
```bash
pip-audit
```