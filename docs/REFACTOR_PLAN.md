# depcheck v1 — Refactor, Performance & Packaging Plan

Status: implementation plan (executed on `feature/v1-refactor`).
Owner: jlaportebot. Target: Python 3.11+, zero-cost, no runtime service dependencies.

---

## 0. Baseline (measured, not assumed)

| Signal | Measurement |
|---|---|
| Test suite | 1844 passed, **1 failed** (`tests/test_diff.py::TestDiffCLI::test_diff_cli_json`) |
| Coverage | 76% total, CI floor 75% |
| Module count / size | 55 modules, 33,106 lines; `cli.py` = 2,997 lines / 28 commands |
| Test size | 39 files, 23,774 lines |
| Network | 2 HTTP round-trips per package, **fully sequential** (60 requests for 30 pkgs) |
| Real-network scan | 22 packages → **5.76 s** (262 ms/pkg) |
| CI on `main` | **RED** (ty `redundant-condition` + pip-audit 18–20 vulns) |
| CI on PRs #105–#108 | **RED** (same two causes) |
| PyPI name `depcheck` | **TAKEN** by an unrelated project → cannot publish under this name |
| README | Documents 7 commands that **do not exist**; their code exists but is orphaned |
| `py.typed` | missing — package ships no typing metadata |
| Release workflow | none — no tags, no releases, no PyPI publish path |

### Root causes behind the baseline

1. **JSON corruption** — every `--json` path prints through a Rich `Console`, which
   soft-wraps at the terminal width and injects a hard newline inside long strings →
   `json.loads()` raises `Invalid control character`. ~40 call sites affected.
2. **No concurrency, no cache** — `scanner.scan_project` loops one package at a time.
3. **CI is permanently red** — `if pyproject_path.is_file() and tomllib:` (stdlib on
   3.11+, so always truthy) trips `ty` with `error-on-warning=true`; the audit job
   installs `pip-audit` whose *own* transitive tree was vulnerable.
4. **CLI is a monolith** — every command lives in one 3k-line file.
5. **Feature code is unreachable** — `predict`, `stack`, `config`, `summary`,
   `workspace`, `remediate`, `annotations` are implemented and tested but never
   registered on the CLI group.
6. **Packaging is not publishable** — name collision, no `py.typed`, no release
   automation, lockfile not used by CI, built wheel never actually installed.

---

## 1. Phase A — Unblock CI (must be first)

- A1. `depcheck/config.py`: drop the always-truthy `and tomllib` guards
  (2 sites). `requires-python = ">=3.11"`, `tomllib` is stdlib.
- A2. Refresh `uv.lock` so the `audit` group resolves
  `filelock>=4.2.1`, `msgpack>=1.2.3`, `urllib3>=2.8.0`, `anyio>=4.14.2`,
  `certifi>=2026.10.18`, `pip>=26.2`. Commit the lockfile; CI uses `--frozen`.
- A3. CI hygiene: `cache-dependency-glob: "uv.lock"`, `uv sync --frozen`,
  drop the per-run `uv lock`.
- A4. `build` job installs the **built wheel** into a clean venv and smoke-tests
  the installed artifact (`depcheck --version`, `depcheck scan --json`).

## 2. Phase B — Correctness: one JSON path, one TOML path, one HTTP path

- B1. New `depcheck/jsonout.py` → `emit_json(payload, stream=None)` writes
  `json.dumps(..., indent=2, default=str)` straight to stdout (no Rich, no
  wrapping, no ANSI). Replace **all** `console.print(json.dumps(...))`,
  `console.print_json(...)` and `print(json.dumps(...))` sites.
- B2. Regression test: every `--json` command's stdout must survive `json.loads`
  with a long path (>200 chars) — the exact case that broke `diff`.
- B3. New `depcheck/toml.py` → single `load_toml(path)` / `loads_toml(text)`
  returning `dict` and raising a typed error instead of `except Exception: pass`
  (7 inline copies across `budget`, `pin`, `policy`, `scanner`, `config`).
- B4. New `depcheck/naming.py` → `normalize_package_name` (PEP 503) as the one
  home; `scanner` re-exports it for backwards compatibility.
- B5. New `depcheck/http.py` → shared pooled `httpx.Client` factory with
  retry/backoff and a shared `User-Agent`; `pypi`, `osv`, `advisories`, `search`
  all use it.
- B6. Unify duplicate models: `licenses.LicenseInfo` vs `models.LicenseInfo`
  (one definition, re-export), `VersionConstraint` (`resolve` vs `conflicts`),
  `ConflictSeverity` (`stack` vs `conflicts`).
- B7. `models.py`: hoist `from packaging.version import Version` to module scope
  (was re-imported on every property access); drop the production `assert`.

## 3. Phase C — Performance

- C1. `depcheck/cache.py` — SQLite cache (WAL, TTL per API, atomic writes) keyed
  by `(api, package, version)`. TTLs: PyPI 1 h, OSV 6 h. `--no-cache`,
  `--cache-ttl`, `DEPCHECK_CACHE_DIR`.
- C2. `depcheck cache clear` / `depcheck cache stats` / `depcheck cache path`.
- C3. Concurrent fetching in `scanner`: `ThreadPoolExecutor` (httpx is sync —
  threads, not asyncio), bounded worker count, deterministic result ordering.
- C4. OSV **batch** queries via `/v1/querybatch` (≤1000 queries/request) →
  1 request instead of N.
- C5. ETag / `If-None-Match` conditional requests for PyPI.
- C6. `--offline` / `--no-network` mode — cache-only, fails loudly on a miss.
- Target: 30 pkgs from 60 sequential requests (~6 s) → ≤10 requests, warm scan
  under 1 s.

## 4. Phase D — Maintainability

- D1. Split `depcheck/cli.py` (2,997 lines) into `depcheck/commands/` — one module
  per command family. `depcheck/cli.py` stays a thin registrar so
  `from depcheck.cli import main` keeps working (11 tests patch
  `depcheck.cli.scan_project`).
- D2. Register the 7 orphaned commands: `annotations`, `predict`, `stack`,
  `config`, `summary`, `workspace`, `remediate`.
- D3. Every command gets a `--json` flag through the shared emitter.
- D4. Shared option decorators (`--config`, `--offline`, `--no-cache`,
  `--cache-ttl`) in `depcheck/commands/_common.py`.

## 5. Phase E — Packaging & release

- E1. Rename the PyPI project to a free name (`depcheck-cli`; console script
  stays `depcheck` so muscle memory works). `depcheck` on PyPI is a different
  project.
- E2. `py.typed` + hatch wheel/sdist targets + `py.typed` included.
- E3. Single source of version truth (`importlib.metadata.version` with fallback).
- E4. `.github/workflows/release.yml` — tag → build → **trusted publishing
  (OIDC)** → GitHub Release.
- E5. `CHANGELOG.md` (Keep a Changelog) + `docs/` usage pages.
- E6. `MANIFEST.in`-equivalent via hatch sdist includes.

## 6. Phase F — Convenience features

- F1. `depcheck init` — scaffold `[tool.depcheck]` config + a GitHub Actions
  workflow that runs `depcheck scan --fail-on vulnerable`.
- F2. `depcheck ci` — one-shot gate: scan + licenses + budget + policy + exit code.
- F3. `--format {table,json,sarif,markdown}` — SARIF for GitHub code scanning,
  Markdown for PR comments.
- F4. `depcheck completions <shell>` (bash/zsh/fish) — native Click support.
- F5. `depcheck badge` — shields.io endpoint from the existing scorecard.
- F6. `depcheck doctor --fix` — actionable auto-fixes (pre-commit / Dependabot).
- F7. `depcheck search` — expose the already-written search module.

## 7. Phase G — Verification gates (all must be green)

1. `pytest -q` → 0 failures (the JSON bug fixed).
2. `pytest --cov=depcheck --cov-fail-under=75` → ≥ 75 % (target higher).
3. `ruff check .` → clean.
4. `ruff format --check .` → clean.
5. `ty check depcheck/` → clean with `error-on-warning = true`.
6. `uv lock --check` → lockfile consistent.
7. `pip-audit` on the `audit` group → 0 known vulnerabilities.
8. `uv build` → sdist + wheel; wheel installed in a **clean venv** and
   `depcheck --version`, `depcheck scan --json` executed from the installed artifact.
9. End-to-end CLI smoke of every registered command (`--help` for all,
   real run for the main ones) with JSON validated by `json.loads`.
10. CI green on the PR; Dependabot PRs #105–#108 resolved.

## 7.5 Phase H — Resume session (2026-11-03)

Phases A–F landed as commits `1afb072`..`87df4df`. The resume session closes
the remaining gaps and ships them.

### H1. Register the newly-written command modules (BLOCKER)

Twelve command modules exist on disk but were never attached to the CLI group,
so `depcheck --help` showed 28 commands while the tree carried 40:

`annotations`, `badge`, `ci`, `completions`, `config`, `init`, `predict`,
`remediate`, `search`, `stack`, `summary`, `workspace`.

- Register all twelve in `depcheck/cli.py::_COMMAND_MODULES`.
- Extend `tests/test_cli_split.py::EXPECTED_COMMANDS` so the structural test
  locks the *complete* set (not a subset) — a command can never silently vanish.
- Add a test that every registered command's `--help` renders and that
  `depcheck --help` lists all of them.

### H2. Fix the defects found in the new command modules

- `commands/remediate.py`: duplicated `--apply requires --repo` guard (dead
  second copy) and a Click flag collision — `--apply` and `--dry-run/--no-dry-run`
  both write `dry_run`, so the last one parsed wins. Replace with a single
  `--apply/--dry-run` boolean pair.
- `commands/predict.py`, `commands/stack.py`: replace the `io.StringIO` +
  `Console(width=1000)` capture hack with a direct `to_dict()` → `jsonout` path.
- `commands/config.py`: `import json` inside the function and a raw
  `json.dumps` bypass of the canonical emitter.
- `commands/summary.py`, `commands/search.py`: route through `jsonout.to_json`.
- `commands/{config,predict,remediate,search,stack,summary,workspace}.py`:
  remove the empty `if TYPE_CHECKING: pass` blocks.
- `depcheck/toml.py`: drop the stray module-level `pass`.
- `depcheck/output.py`, `depcheck/formats.py`: remove production `assert`s
  (they vanish under `python -O`).
- `depcheck/scorecard.py`, `depcheck/search.py`, `depcheck/workspace_report.py`:
  use the canonical `jsonout` serializer instead of raw `json.dumps`.

### H3. Missing convenience features

- **H3a `depcheck cache`** — new command group with `clear`, `stats`, `path`
  subcommands over the existing `depcheck/cache.py` SQLite store.
- **H3b `--config PATH`** — global flag pointing at an explicit config file;
  `DEPCHECK_*` environment variables override file values.
- **H3c `depcheck doctor --fix`** — write the actionable fixes the doctor
  already knows how to recommend (Dependabot config, pre-commit hook config).
- **H3d `depcheck scan --format`** — already implemented; keep `--json` as an
  alias for `--format json` and make the other formats reachable from `scan`.

### H4. Docs and packaging polish

- README: document every registered command (the table currently lists 19 of 40),
  the `--format` flag, the cache commands, `depcheck init`, `depcheck ci`,
  `depcheck completions`, and the `depcheck-cli` PyPI name.
- `docs/` usage pages: `docs/commands.md`, `docs/ci.md`, `docs/configuration.md`.
- `CHANGELOG.md`: move the v1 work out of `[Unreleased]`.
- CI hygiene: `cache-dependency-glob: "uv.lock"`, `uv sync --frozen`,
  build job installs the built wheel and smoke-tests the installed artifact.

### H5. Verification gates (all must be green before merge)

1. `pytest -q` → 0 failures.
2. `pytest --cov=depcheck --cov-fail-under=75` → ≥ 75 %.
3. `ruff check .` → clean.
4. `ruff format --check .` → clean.
5. `ty check depcheck/` → clean with `error-on-warning = true`.
6. `uv lock --check` → lockfile consistent.
7. `pip-audit` → 0 known vulnerabilities.
8. `uv build` → sdist + wheel; wheel installed in a **clean venv** and
   `depcheck --version`, `depcheck scan --json` executed from the installed artifact.
9. End-to-end smoke of **every** registered command (`--help` for all, real run
   for the main ones) with JSON validated by `json.loads`.
10. CI green on the PR; PR #109 updated with the full story.

## 8. Explicit non-goals

- No runtime daemon, no paid API, no telemetry, no auth requirement.
- No async rewrite of the whole codebase (threads + batching give the win at a
  fraction of the risk).
- No breaking change to the `depcheck` console-script name.
