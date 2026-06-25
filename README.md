# depcheck

[![CI](https://github.com/jlaportebot/depcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/jlaportebot/depcheck/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/depcheck.svg)](https://pypi.org/project/depcheck/)
[![Python versions](https://img.shields.io/pypi/pyversions/depcheck.svg)](https://pypi.org/project/depcheck/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

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
- 📝 **GitHub Actions annotations** — `depcheck annotations` for inline CI error reporting
- 📦 **Dependency tree** — ASCII/JSON tree view with health status (`depcheck tree`)
- 📊 **Project summary** — quick health score with letter grade (`depcheck summary`)
- 🔬 **Doctor** — best practices check for CI, pre-commit, Dependabot, security files, etc. (`depcheck doctor`)
- 📦 **Workspace/monorepo support** — scan uv/Poetry/Hatch/PDM workspaces (`depcheck workspace`)
- 🔮 **Deprecation prediction** — predict version releases and detect deprecation risk (`depcheck predict`)
- 🏗️ **Tech stack analysis** — detect conflicts and known incompatibilities (`depcheck stack`)
- ⚙️ **Configuration** — YAML/TOML config with validation and generation (`depcheck config`)
- 🔄 **Automated remediation** — create GitHub PRs for dependency updates (`depcheck remediate`)
- 📈 **Drift detection** — track dependency changes across git history (`depcheck history`)
- 🐍 **Python compatibility** — check Python version compatibility (`depcheck compat`)

## Installation

```bash
pip install depcheck
```

## Quick Start

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

### Outdated dependency analysis with upgrade paths

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

### Display dependency tree

```bash
# Tree view with health status
depcheck tree

# JSON output for tooling
depcheck tree --json

# Control depth
depcheck tree --max-depth 5

# Disable highlighting for clean output
depcheck tree --no-highlight
```

### Quick health summary with letter grade

```bash
depcheck summary
depcheck summary --json
depcheck summary --no-vuln-check --quiet
```

### Project best practices check

```bash
depcheck doctor
depcheck doctor --json
depcheck doctor /path/to/project
```

### Scan workspace/monorepo

```bash
depcheck workspace
depcheck workspace /path/to/monorepo
depcheck workspace --json
```

### Deprecation prediction and risk analysis

```bash
depcheck predict
depcheck predict --json
depcheck predict --fail-on high
depcheck predict /path/to/project
```

### Tech stack analysis

```bash
depcheck stack
depcheck stack --json
depcheck stack --check-licenses
depcheck stack /path/to/project
```

### Configuration management

```bash
# Show current config
depcheck config

# Validate config
depcheck config --validate

# Generate default config
depcheck config --init
depcheck config --init --output pyproject.toml
```

### Python version compatibility

```bash
depcheck compat
depcheck compat --target 3.13
depcheck compat --target 3.11 --json
```

### Dependency history / drift over time

```bash
depcheck history
depcheck history --from-commit abc123 --to-commit def456
depcheck history --max-commits 50
depcheck history --json
```

### Automated remediation PRs

```bash
depcheck remediate --repo owner/repo
depcheck remediate --repo owner/repo --auto-merge --base-branch develop
depcheck remediate --repo owner/repo --dry-run --json
depcheck remediate /path/to/project --repo owner/repo --label security --reviewer @me
```

### GitHub Actions annotations

```bash
depcheck annotations
depcheck annotations --output annotations.txt
depcheck annotations --fail-on vulnerable
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

## Configuration

Create a `depcheck.yaml` or `depcheck.toml` configuration file:

```yaml
# depcheck.yaml
fail_on: "warning"
allowed_license_categories:
  - "permissive"
  - "public_domain"
denied_licenses:
  - "GPL-3.0"
  - "AGPL-3.0"
```

Or in `pyproject.toml`:

```toml
[tool.depcheck]
fail_on = "warning"
allowed_license_categories = ["permissive", "public_domain"]
denied_licenses = ["GPL-3.0", "AGPL-3.0"]

[tool.depcheck.budget]
max_packages = 100
max_total_download_kb = 50000
max_transitive_depth = 3
allowed_license_categories = ["permissive"]
denied_packages = ["unwanted-package"]
required_packages = ["setuptools"]

[tool.depcheck.policy.rules]
- name = "no-deprecated"
  category = "maintenance"
  severity = "error"
  description = "Flag deprecated packages"
```

## Commands Reference

| Command | Description |
|---------|-------------|
| `scan` | Scan project for dependency health issues |
| `annotations` | Generate GitHub Actions annotations |
| `tree` | Display dependency tree with health status |
| `diff` | Compare two dependency files or detect lockfile drift |
| `export` | Generate SBOM (CycloneDX, SPDX, summary) |
| `license` | Check license compliance |
| `outdated` | Analyze outdated dependencies with upgrade paths |
| `graph` | Generate interactive HTML dependency graph |
| `why` | Trace why a dependency exists in your project |
| `watch` | Watch for dependency file changes in real-time |
| `predict` | Predict version releases and deprecation risk |
| `stack` | Analyze tech stack and detect conflicts |
| `config` | Show, validate, or generate configuration |
| `doctor` | Check project for best practices |
| `summary` | Quick health summary with letter grade |
| `workspace` | Scan workspace/monorepo |
| `history` | Track dependency changes across git history |
| `remediate` | Create automated remediation PRs |
| `compat` | Check Python version compatibility |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Quick start for contributors:**

```bash
git clone https://github.com/jlaportebot/depcheck.git
cd depcheck
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest -v

# Lint & format
ruff check .
ruff format --check .
```

**Good first issues:** Look for the [`good first issue` label](https://github.com/jlaportebot/depcheck/issues?q=label%3A%22good+first+issue%22) — we'll mentor you through it.

**Questions?** Open a [Discussion](https://github.com/jlaportebot/depcheck/discussions) or [issue](https://github.com/jlaportebot/depcheck/issues/new/choose).

## License

MIT — see [LICENSE](LICENSE) for details.

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). We follow the Contributor Covenant.

---

**depcheck** — Built with 🦞 by Mister Lobster