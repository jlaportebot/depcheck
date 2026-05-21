# depcheck

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/jlaportebot/depcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/jlaportebot/depcheck/actions/workflows/ci.yml)

**A dependency health checker for Python projects.**

`depcheck` scans your Python project's dependencies and reports on their health — checking for outdated packages, known vulnerabilities (CVEs), unmaintained packages, and yanked or removed packages.

## Features

- 🔍 **Multi-format support** — scans `requirements.txt`, `pyproject.toml`, and `Pipfile`
- 🛡️ **Vulnerability scanning** — checks packages against the [OSV.dev](https://osv.dev) database
- 📦 **Outdated detection** — compares installed versions against the latest on PyPI
- ⏰ **Unmaintained detection** — flags packages with no updates in over a year
- 🚫 **Yanked/removed detection** — identifies packages no longer available on PyPI
- 🎨 **Beautiful output** — Rich-powered terminal tables with color-coded health status
- 🤖 **CI/CD friendly** — JSON output mode and configurable exit codes for automation

## Installation

```bash
pip install depcheck
```

## Usage

### Scan the current directory

```bash
depcheck scan
```

### Scan a specific project path

```bash
depcheck scan /path/to/my/project
```

### JSON output for CI/CD pipelines

```bash
depcheck scan --json
```

### Fail on vulnerabilities (useful in CI)

```bash
depcheck scan --fail-on vulnerable
```

### Fail on any unhealthy package

```bash
depcheck scan --fail-on any
```

### Fail on outdated packages

```bash
depcheck scan --fail-on outdated
```

### Combine options

```bash
depcheck scan /path/to/project --json --fail-on vulnerable
```

## Health Status

Each package is assigned a health status with color-coded output:

| Status | Icon | Color | Meaning |
|--------|------|-------|---------|
| Healthy | 🟢 | Green | Package is up-to-date with no known issues |
| Outdated | 🟡 | Yellow | A newer version is available on PyPI |
| Vulnerable | 🔴 | Red | Known CVEs exist for this package version |
| Unmaintained | 🟡 | Yellow | No release in over 1 year |
| Yanked | 🔴 | Red | Package or version has been yanked from PyPI |
| Removed | 🔴 | Red | Package no longer exists on PyPI |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All packages healthy (or no `--fail-on` specified) |
| 1 | Failed due to `--fail-on` condition met |
| 2 | Error during scanning |

## Screenshots

<!-- Screenshots coming soon! -->

*Placeholder — screenshots will be added after first release.*

## How It Works

1. **Discovery** — `depcheck` looks for `requirements.txt`, `pyproject.toml`, or `Pipfile` in your project directory
2. **Parsing** — Extracts package names and version specifiers
3. **PyPI Lookup** — Queries the PyPI JSON API for each package to get latest versions, release dates, and yanked status
4. **Vulnerability Check** — Queries the [OSV.dev API](https://osv.dev) for known vulnerabilities affecting each package version
5. **Report** — Displays a rich, color-coded summary table

## Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository at [github.com/jlaportebot/depcheck](https://github.com/jlaportebot/depcheck)
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development setup

```bash
git clone https://github.com/jlaportebot/depcheck.git
cd depcheck
pip install -e ".[dev]"
```

### Running tests

```bash
pytest
```

### Code style

This project uses [Ruff](https://docs.astral.sh/ruff/) for linting and formatting.

```bash
ruff check .
ruff format .
```

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
