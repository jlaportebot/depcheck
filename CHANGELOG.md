# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Global `--config` flag** — point `depcheck` at an explicit config file instead of `pyproject.toml` (`depcheck --config path/to/pyproject.toml scan ...`).
- **`DEPCHECK_*` environment overrides** — `DEPCHECK_FAIL_ON`, `DEPCHECK_CHECK_VULNERABILITIES`, `DEPCHECK_CHECK_LICENSES`, `DEPCHECK_QUIET`, `DEPCHECK_OUTPUT_JSON` override config-file values (explicit CLI flags win over env, which win over the config file).
- **`depcheck doctor --fix` / `--dry-run`** — automatically pin unpinned requirements in `requirements.txt` to their latest stable version from PyPI; `--dry-run` previews changes without writing files.
- **Conditional (ETag) requests** — PyPI and OSV clients now send `If-None-Match` and reuse `304 Not Modified` responses, so repeated scans avoid re-downloading unchanged package metadata.
- **Unified HTTP client** — PyPI and OSV clients both build via `depcheck.http.build_client()`, sharing the pooled client, retry/backoff policy, and `User-Agent`.

### Changed
- **Distribution renamed to `depcheck-cli` on PyPI** — The PyPI package name `depcheck` is already taken by an unrelated project (flix-tech/depcheck). The console command remains `depcheck` so existing workflows and muscle memory continue to work.
  - **Migration note**: `pip install depcheck` now installs a DIFFERENT, unrelated package. To install this tool, use `pip install depcheck-cli`.

### Fixed
- **Cache TTL expired-entry bug** — `ResponseCache.set()` no longer drops entries whose TTL had already expired, so cache stats and hit counting are correct.
- **`annotations` command shadowing** — removed `from __future__ import annotations` from `depcheck/commands/__init__.py` so the `annotations` subcommand registers correctly instead of returning `__future__._Feature`.

## [0.4.0] - 2026-11-02

### Added
- **JSON output corruption fix** — Fixed a bug where JSON output (`--format json`) could be corrupted by interleaved log/rich output. JSON is now cleanly separated and machine-parseable.
- **Persistent TTL cache with offline mode** — Added a persistent on-disk cache (`--cache-dir`, `--cache-ttl`) with `--offline` flag for fully disconnected operation. Cache survives process restarts and respects TTL.
- **Batched/concurrent network calls** — PyPI and OSV API calls are now batched and executed concurrently, significantly reducing scan time for projects with many dependencies.
- **Packaging & release automation** — Project is now publishable as `depcheck-cli` on PyPI with trusted publishing (OIDC). Includes GitHub Actions release workflow triggered by `v*` tags.

### Changed
- **CI repair** — Fixed `ty` redundant-condition warnings and integrated `pip-audit` lockfile scanning into CI.
- **Minimum Python version** — Confirmed support for Python 3.11, 3.12, and 3.13.

### Fixed
- Various edge cases in dependency resolution and vulnerability matching.

## [0.3.0] - 2026-XX-XX

### Added
- Initial public release with core dependency health checking features.
- Commands: `scan`, `doctor`, `outdated`, `audit`, `why`, `pin`, `export`, `graph`, `tree`, `diff`, `history`, `watch`, `config`.
- Rich terminal output with multiple formats (table, json, csv, sarif, markdown).
- PyPI and OSV vulnerability database integration.
- License scanning and policy enforcement.
- Dependency conflict detection and resolution suggestions.
- GitHub PR integration for automated dependency updates.