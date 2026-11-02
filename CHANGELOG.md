# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Distribution renamed to `depcheck-cli` on PyPI** — The PyPI package name `depcheck` is already taken by an unrelated project (flix-tech/depcheck). The console command remains `depcheck` so existing workflows and muscle memory continue to work.
  - **Migration note**: `pip install depcheck` now installs a DIFFERENT, unrelated package. To install this tool, use `pip install depcheck-cli`.

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