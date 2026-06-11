# Contributing to depcheck

Thanks for wanting to contribute! depcheck is a dependency health checker for Python projects — scanning for vulnerabilities, outdated packages, unmaintained deps, license issues, and more. All help is welcome.

## Quick Start

```bash
# Clone and set up
git clone https://github.com/jlaportebot/depcheck.git
cd depcheck
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest -v

# Run linting
ruff check .
ruff format --check .

# Run the CLI
depcheck --help
```

## How to Contribute

### 1. Find Something to Work On

- Check [open issues](https://github.com/jlaportebot/depcheck/issues) — look for `good first issue`, `help wanted`, `docs`
- Have an idea? Open an issue first to discuss before building
- Found a bug? Report it with the bug template

### 2. Make Your Changes

```bash
# Create a branch
git checkout -b feature/your-thing
# or
git checkout -b fix/your-thing
# or
git checkout -b docs/your-thing

# Make changes, test locally
pytest -v
ruff check .
ruff format --check .
```

### 3. Submit a PR

- Push your branch and open a PR against `main`
- Fill out the PR template
- Link the issue: `Fixes #123` or `Closes #123`
- CI must pass (tests, lint, format)

## Code Standards

### Python Style

- **ruff** for linting + formatting — enforced in CI (config in `pyproject.toml`)
- **Python 3.9+** — use modern syntax
- Line length: 100 chars

### Architecture

```
src/depcheck/
├── cli.py              # Click CLI entry point (all commands)
├── scanner.py          # Core scanning logic
├── models.py           # Data classes (Package, ScanResult, etc.)
├── pypi.py             # PyPI API client
├── osv.py              # OSV.dev vulnerability client
├── licenses.py         # License classification & compliance
├── graph.py            # Dependency graph & visualization
├── export.py           # SBOM export (CycloneDX, SPDX)
├── diff.py             # Dependency diff & drift detection
├── outdated.py         # Outdated analysis
├── watch.py            # File watching
└── utils.py            # Helpers
```

**Key principles:**
- CLI is thin — logic lives in library functions
- External API calls (PyPI, OSV) are isolated in dedicated modules
- Rich terminal output for humans, JSON for machines
- Optional features (licenses, graph, watch) don't break core if deps missing

### Testing

- **Unit tests**: `tests/test_*.py` — test individual functions/classes
- **Integration tests**: `tests/test_cli.py` — end-to-end CLI runs
- **Fixtures**: `tests/conftest.py` — sample requirements, mock responses

```bash
# Run all tests
pytest -v

# With coverage
pytest --cov=depcheck --cov-report=term-missing
```

### Adding a New CLI Command

1. Add command function in `cli.py` with Click decorators
2. Implement logic in appropriate module (or new module)
3. Add tests in `tests/test_cli.py`
4. Update README with usage example

### Adding a New Export Format

1. Add formatter function in `export.py`
2. Register in `EXPORT_FORMATS` dict
3. Add CLI option in `cli.py`
4. Add tests
5. Document in README

## PR Requirements

- [ ] Tests pass (`pytest -v`)
- [ ] Lint clean (`ruff check .`)
- [ ] Format clean (`ruff format --check .`)
- [ ] No debug code left (`print()`, `breakpoint()`, commented-out code)
- [ ] Docstrings on public functions/classes
- [ ] New code has tests
- [ ] Updated docs if user-facing behavior changed

## Communication

- **Issues** — Bugs, features, questions
- **Discussions** — General chat, ideas, "how do I...?"
- **PRs** — Code review happens here

Response time: usually within a day or two.

## Recognition

All contributors get credited in releases. We value code, docs, tests, bug reports, and answering questions.

---

**Questions?** Open a [Discussion](https://github.com/jlaportebot/depcheck/discussions) or comment on an issue.