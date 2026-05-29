# depcheck

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/jlaportebot/depcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/jlaportebot/depcheck/actions/workflows/ci.yml)

**A dependency health checker for Python projects.**

`depcheck` scans your Python project's dependencies and reports on their health — checking for outdated packages, known vulnerabilities (CVEs), unmaintained packages, yanked or removed packages, and license compliance.

## Features

- 🔍 **Multi-format support** — scans `requirements.txt`, `pyproject.toml`, and `Pipfile`
- 🛡️ **Vulnerability scanning** — checks packages against the [OSV.dev](https://osv.dev) database
- 📦 **Outdated detection** — compares installed versions against the latest on PyPI
- ⏰ **Unmaintained detection** — flags packages with no updates in over a year
- 🚫 **Yanked/removed detection** — identifies packages no longer available on PyPI
- 📋 **SBOM export** — generate Software Bills of Materials in CycloneDX and SPDX formats (`depcheck export`)
- ⚖️ **License compliance** — license classification with SPDX identifiers and compliance checking
- 🎨 **Beautiful output** — Rich-powered terminal tables with color-coded health status
- 🔄 **Dependency diff** — compare two requirement files or detect lockfile drift (`depcheck diff`)
- 📈 **Outdated analysis** — upgrade path tracking with semver classification, risk assessment, and changelog links (`depcheck outdated`)
- 🔗 **Dependency chain tracing** — find out why a package is in your project with `depcheck why <package>`
- 📊 **Dependency graph** — interactive HTML visualization with D3.js force-directed layout (`depcheck graph`)
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

### License compliance checking

```bash
# Enable license scanning for all dependencies
depcheck scan --check-licenses

# Only allow permissive and public-domain licenses (flags copyleft/restricted as non-compliant)
depcheck scan --check-licenses --allow-license permissive --allow-license public_domain

# Deny specific licenses
depcheck scan --check-licenses --deny-license GPL-3.0 --deny-license AGPL-3.0

# Fail CI if any license issues found
depcheck scan --check-licenses --fail-on license

# Combine license options (specifying --allow-license or --deny-license enables checking automatically)
depcheck scan --allow-license permissive --deny-license GPL-3.0
```

### Dependency graph visualization

```bash
# Generate an interactive HTML dependency graph
depcheck graph

# Specify output file and project path
depcheck graph /path/to/project -o deps.html

# Control tree depth and check licenses
depcheck graph --max-depth 5 --check-licenses

# Skip vulnerability checks for faster results
depcheck graph --no-vuln-check
```

The generated HTML file includes:
- **D3.js force-directed graph** with nodes colored by health status
- **Click-to-inspect** any node for version, license, and vulnerability details
- **Search/filter** packages by name
- **Zoom and pan** to navigate large dependency trees
- **Export** as SVG or PNG directly from the browser

### Compare dependency files

```bash
depcheck diff requirements.old.txt requirements.new.txt
```

### Outdated dependency analysis

```bash
# Check for outdated dependencies with upgrade path analysis
depcheck outdated

# Show pip upgrade commands grouped by risk level
depcheck outdated --show-commands

# JSON output for CI/CD
depcheck outdated --json

# Fail CI if major upgrades available (breaking changes)
depcheck outdated --fail-on major

# Fail on any outdated dependency
depcheck outdated --fail-on any
```

### Compare as JSON (CI/CD)

```bash
depcheck diff --json requirements.old.txt requirements.new.txt
```

### Detect lockfile drift

```bash
depcheck diff --drift requirements.txt requirements.lock
```

### Fail on any change (CI gate)

```bash
depcheck diff --fail-on-change requirements.old.txt requirements.new.txt
```

### Show traditional unified diff

```bash
depcheck diff --unified v1.txt v2.txt
```

### Watch for dependency changes in real-time

```bash
# Monitor current directory for dependency file changes
depcheck watch

# Watch a specific project with custom debounce
depcheck watch /path/to/project --debounce 5

# CI guard: exit immediately if vulnerabilities detected
depcheck watch --exit-on-issue --fail-on vulnerable

# Watch with license compliance
depcheck watch --check-licenses --deny-license GPL-3.0
```

### Generate an SBOM (Software Bill of Materials)

```bash
depcheck export --format cyclonedx
depcheck export --format spdx --output sbom.json
depcheck export --format summary
depcheck export --format cyclonedx --check-licenses --output bom.cdx.json
```

### Export without vulnerability checks (faster)

```bash
depcheck export --format cyclonedx --no-vuln-check
```

### Trace why a dependency exists

```bash
depcheck why urllib3
depcheck why certifi /path/to/project
depcheck why setuptools --json
depcheck why pillow --max-depth 6
depcheck why numpy --no-vuln-check
```

`depcheck why` resolves the full dependency graph and finds all paths from your direct dependencies to the target package — answering the common question: *why is this package in my project?*

## Diff Change Types

| Change | Symbol | Meaning |
|--------|--------|---------|
| Added | `+` | Package exists only in the new file |
| Removed | `-` | Package exists only in the old file |
| Upgraded | `↑` | Pinned version increased |
| Downgraded | `↓` | Pinned version decreased |
| Specifier changed | `~` | Version specifier changed (e.g., `>=2.0` → `>=3.0`) |
| Unpinned | `⚠` | Went from pinned version to version range |
| Pinned | `✓` | Went from version range to pinned version |
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

## SBOM Export Formats

`depcheck export` supports industry-standard SBOM formats for supply chain transparency and regulatory compliance (EU CRA, US EO 14028):

| Format | Standard | Use Case |
|--------|----------|----------|
| `cyclonedx` | OWASP CycloneDX 1.6 | Supply chain security, vulnerability correlation |
| `spdx` | SPDX 2.3 | License compliance, open source auditing |
| `summary` | depcheck custom | Quick human review, CI dashboards |

All formats include package names, versions, and [PURLs](https://github.com/package-url/purl-spec). CycloneDX output includes vulnerability data with severity ratings; SPDX output includes license declarations and dependency relationships.

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
3. **PyPI Lookup** — Queries the PyPI JSON API for each package to get latest versions, release dates, yanked status, and license metadata
4. **Vulnerability Check** — Queries the [OSV.dev API](https://osv.dev) for known vulnerabilities affecting each package version
5. **License Classification** — Normalizes license identifiers to SPDX IDs, classifies them into categories (permissive, copyleft, restricted, public domain), and checks against your compliance policy
6. **Report** — Displays a rich, color-coded summary table with license compliance status

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
