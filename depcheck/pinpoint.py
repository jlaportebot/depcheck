"""Version pinning analysis for depcheck.

Analyzes how dependencies are version-pinned and recommends optimal
pinning strategies. Proper pinning is critical for reproducible builds
and security, but over-pinning prevents beneficial updates.

Features:
- Pinning style detection: exact (==), compatible (~=), minimum (>=), loose (unpinned)
- Pinning coverage: what % of dependencies are pinned vs unpinned
- Security analysis: which unpinned packages should be pinned
- Flexibility analysis: which over-pinned packages could use ~= instead of ==
- Pinning recommendations per-package with rationale
- Project-level pinning health score
- Generate pinning policy files (pip constraints format)
- Deprecation risk: packages pinned to very old versions
"""

from __future__ import annotations

import enum
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from depcheck.models import ParsedDependency
from depcheck.pypi import PyPIClient
from depcheck.scanner import (
    normalize_package_name,
    parse_pipfile,
    parse_pyproject_toml,
    parse_requirements_txt,
)


# ── Enums & Constants ────────────────────────────────────────────────────


class PinStyle(enum.Enum):
    """Version pinning style for a dependency."""

    EXACT = "exact"  # ==1.2.3
    COMPATIBLE = "compatible"  # ~=1.2 (PEP 440 compatible release)
    MINIMUM = "minimum"  # >=1.2
    RANGE = "range"  # >=1.2,<2.0
    WILDCARD = "wildcard"  # 1.* or *
    UNPINNED = "unpinned"  # no version specifier at all


class PinRecommendation(enum.Enum):
    """Pin recommendation for a dependency."""

    PIN_EXACT = "pin_exact"  # Should use == (security-critical or 0.x)
    PIN_COMPATIBLE = "pin_compatible"  # Should use ~= (stable packages)
    RELAX_RANGE = "relax_range"  # Currently == but could use ~= or >=
    KEEP = "keep"  # Current pinning is appropriate
    ADD_PIN = "add_pin"  # Currently unpinned, should be pinned


# ── Data Models ──────────────────────────────────────────────────────────


@dataclass
class PinInfo:
    """Pinning information for a single dependency."""

    name: str
    raw_specifier: str = ""
    style: PinStyle = PinStyle.UNPINNED
    version: str | None = None
    latest_version: str | None = None
    recommendation: PinRecommendation = PinRecommendation.KEEP
    rationale: str = ""
    risk_score: float = 0.0  # 0-10, higher = more risk from current pinning

    @property
    def is_pinned(self) -> bool:
        """Whether this dependency has any version constraint."""
        return self.style != PinStyle.UNPINNED

    @property
    def is_exact_pinned(self) -> bool:
        """Whether this dependency uses exact version pinning."""
        return self.style == PinStyle.EXACT

    @property
    def is_unpinned(self) -> bool:
        """Whether this dependency has no version constraint."""
        return self.style == PinStyle.UNPINNED

    @property
    def version_age_days(self) -> int | None:
        """Days since the pinned version was released (None if unpinned)."""
        # This would need PyPI release date data for accurate results.
        # For now, returns None — actual implementation would query release dates.
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "raw_specifier": self.raw_specifier,
            "style": self.style.value,
            "version": self.version,
            "latest_version": self.latest_version,
            "recommendation": self.recommendation.value,
            "rationale": self.rationale,
            "risk_score": round(self.risk_score, 1),
            "is_pinned": self.is_pinned,
        }


@dataclass
class PinReport:
    """Complete pinning analysis for a project."""

    project_path: str
    pins: list[PinInfo] = field(default_factory=list)
    total_dependencies: int = 0
    pinned_count: int = 0
    exact_pinned_count: int = 0
    compatible_pinned_count: int = 0
    minimum_pinned_count: int = 0
    range_pinned_count: int = 0
    unpinned_count: int = 0
    wildcard_count: int = 0
    health_score: float = 0.0  # 0-100
    recommendations: list[PinInfo] = field(default_factory=list)

    @property
    def pin_coverage(self) -> float:
        """Percentage of dependencies that are pinned."""
        if self.total_dependencies == 0:
            return 100.0
        return (self.pinned_count / self.total_dependencies) * 100

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "project_path": self.project_path,
            "summary": {
                "total_dependencies": self.total_dependencies,
                "pinned_count": self.pinned_count,
                "exact_pinned_count": self.exact_pinned_count,
                "compatible_pinned_count": self.compatible_pinned_count,
                "minimum_pinned_count": self.minimum_pinned_count,
                "range_pinned_count": self.range_pinned_count,
                "unpinned_count": self.unpinned_count,
                "wildcard_count": self.wildcard_count,
                "pin_coverage_pct": round(self.pin_coverage, 1),
                "health_score": round(self.health_score, 1),
            },
            "pins": [p.to_dict() for p in self.pins],
            "recommendations": [r.to_dict() for r in self.recommendations],
        }


# ── Pin Detection ────────────────────────────────────────────────────────


def _detect_pin_style(specifier: str) -> PinStyle:
    """Detect the pinning style from a version specifier.

    Args:
        specifier: The version specifier string (e.g., "==1.2.3", ">=1.0,<2.0").

    Returns:
        The detected PinStyle.
    """
    if not specifier or specifier.strip() == "":
        return PinStyle.UNPINNED

    spec = specifier.strip()

    # Exact: ==1.2.3 or ===1.2.3
    if spec.startswith("=="):
        return PinStyle.EXACT

    # Compatible: ~=1.2
    if spec.startswith("~="):
        return PinStyle.COMPATIBLE

    # Wildcard: 1.* or *
    if "*" in spec:
        return PinStyle.WILDCARD

    # Range: >=1.0,<2.0 (multiple specifiers)
    if "," in spec:
        return PinStyle.RANGE

    # Minimum: >=1.0 or >1.0
    if spec.startswith(">=") or spec.startswith(">"):
        return PinStyle.MINIMUM

    # Also handle <= and < (ceiling constraints)
    if spec.startswith("<=") or spec.startswith("<"):
        return PinStyle.RANGE

    # Also handle !=
    if spec.startswith("!="):
        return PinStyle.RANGE

    return PinStyle.UNPINNED


def _extract_pinned_version(specifier: str, style: PinStyle) -> str | None:
    """Extract the pinned version from a specifier.

    Args:
        specifier: The version specifier string.
        style: The pinning style.

    Returns:
        The pinned version string, or None if not applicable.
    """
    if style == PinStyle.EXACT:
        # ==1.2.3 -> 1.2.3
        match = re.match(r"^==\s*(.+)$", specifier.strip())
        if match:
            return match.group(1).strip()

    if style == PinStyle.COMPATIBLE:
        # ~=1.2.3 -> 1.2.3 (the minimum compatible version)
        match = re.match(r"^~=\s*(.+)$", specifier.strip())
        if match:
            return match.group(1).strip()

    if style == PinStyle.MINIMUM:
        # >=1.2.3 -> 1.2.3
        match = re.match(r"^>=\s*(.+)$", specifier.strip())
        if match:
            return match.group(1).strip()

    if style == PinStyle.WILDCARD:
        # 1.* -> 1 (just the major)
        match = re.match(r"^(\d+)\.\*$", specifier.strip())
        if match:
            return match.group(1)

    return None


def _generate_recommendation(
    pin: PinInfo,
    pypi: PyPIClient,
) -> tuple[PinRecommendation, str, float]:
    """Generate a pinning recommendation for a dependency.

    Args:
        pin: The pin info to analyze.
        pypi: PyPI client for checking package metadata.

    Returns:
        Tuple of (recommendation, rationale, risk_score).
    """
    risk_score = 0.0

    if pin.is_unpinned:
        # Unpinned dependency — check if it should be pinned
        info = pypi.get_package_info(pin.name)
        if info is None:
            return PinRecommendation.KEEP, "Package not found on PyPI", 0.0

        # Check if it's a 0.x version (pre-release, should be pinned)
        latest = info.get("info", {}).get("version", "")
        try:
            ver = Version(latest)
            if ver.major == 0:
                return (
                    PinRecommendation.PIN_EXACT,
                    f"Pre-1.0 package (v{latest}) — pin exact for stability",
                    8.0,
                )
        except Exception:
            pass

        # Check if package has vulnerabilities (from OSV would be ideal,
        # but we'll use heuristic: popular packages with many releases)
        releases = info.get("releases", {})
        release_count = len(releases)

        if release_count > 50:
            # Many releases = active package = risk of breaking changes
            return (
                PinRecommendation.ADD_PIN,
                f"Active package ({release_count} releases) — add at least a minimum pin (>=)",
                5.0,
            )
        elif release_count > 10:
            return (
                PinRecommendation.ADD_PIN,
                f"Moderately active package ({release_count} releases) — consider pinning",
                3.0,
            )
        else:
            return (
                PinRecommendation.KEEP,
                f"Stable package ({release_count} releases) — unpinned is acceptable",
                1.0,
            )

    if pin.is_exact_pinned:
        # Exact pin — check if it's too restrictive
        if pin.latest_version and pin.version:
            try:
                pinned_ver = Version(pin.version)
                latest_ver = Version(pin.latest_version)

                if pinned_ver.major == 0:
                    return PinRecommendation.KEEP, "Pre-1.0 exact pin is appropriate", 1.0

                if latest_ver.major > pinned_ver.major:
                    # Pinned to old major version
                    risk_score = 7.0
                    return (
                        PinRecommendation.RELAX_RANGE,
                        f"Pinned to v{pin.version} but v{pin.latest_version} available — "
                        f"consider ~= for compatible updates within major version",
                        risk_score,
                    )

                if latest_ver.minor > pinned_ver.minor + 3:
                    # Pinned to old minor version
                    risk_score = 4.0
                    return (
                        PinRecommendation.RELAX_RANGE,
                        f"Pinned to v{pin.version} (several minor versions behind) — "
                        f"consider ~= or >= to allow patch/minor updates",
                        risk_score,
                    )

            except Exception:
                pass

        return PinRecommendation.KEEP, "Exact pin is appropriate", 0.5

    if pin.style == PinStyle.COMPATIBLE:
        return PinRecommendation.KEEP, "Compatible pinning (~=) is ideal", 0.5

    if pin.style == PinStyle.MINIMUM:
        # >= pin — check if it needs an upper bound
        return (
            PinRecommendation.KEEP,
            "Minimum pin (>=) allows updates but risks breaking changes on major bumps",
            3.0,
        )

    if pin.style == PinStyle.RANGE:
        return PinRecommendation.KEEP, "Range pin provides good balance", 1.0

    if pin.style == PinStyle.WILDCARD:
        return (
            PinRecommendation.PIN_COMPATIBLE,
            "Wildcard (*) is too loose — use ~= for compatible updates",
            6.0,
        )

    return PinRecommendation.KEEP, "", 0.0


# ── Report Building ──────────────────────────────────────────────────────


def build_pin_report(
    project_path: str,
) -> PinReport:
    """Build a complete pinning analysis for a project.

    Args:
        project_path: Path to the project directory.

    Returns:
        PinReport with pinning analysis.
    """
    report = PinReport(project_path=project_path)

    # Parse all dependency files
    path = Path(project_path)
    all_deps: list[ParsedDependency] = []
    seen: set[str] = set()

    for parser, filepath in [
        (parse_requirements_txt, path / "requirements.txt"),
        (parse_pyproject_toml, path / "pyproject.toml"),
        (parse_pipfile, path / "Pipfile"),
    ]:
        if filepath.exists():
            for dep in parser(filepath):
                norm = normalize_package_name(dep.name)
                if norm not in seen:
                    seen.add(norm)
                    all_deps.append(dep)

    # Check requirements/ directory
    req_dir = path / "requirements"
    if req_dir.exists() and req_dir.is_dir():
        for req in sorted(req_dir.glob("*.txt")):
            for dep in parse_requirements_txt(req):
                norm = normalize_package_name(dep.name)
                if norm not in seen:
                    seen.add(norm)
                    all_deps.append(dep)

    report.total_dependencies = len(all_deps)

    # Analyze each dependency
    with PyPIClient() as pypi:
        for dep in all_deps:
            norm_name = normalize_package_name(dep.name)
            specifier = dep.specifier or ""

            style = _detect_pin_style(specifier)
            version = _extract_pinned_version(specifier, style) or dep.version
            latest = pypi.get_latest_version(norm_name)

            pin = PinInfo(
                name=norm_name,
                raw_specifier=specifier,
                style=style,
                version=version,
                latest_version=latest,
            )

            # Generate recommendation
            rec, rationale, risk = _generate_recommendation(pin, pypi)
            pin.recommendation = rec
            pin.rationale = rationale
            pin.risk_score = risk

            report.pins.append(pin)

            # Track if there's an actionable recommendation
            if rec != PinRecommendation.KEEP:
                report.recommendations.append(pin)

    # Calculate counts
    report.pinned_count = sum(1 for p in report.pins if p.is_pinned)
    report.exact_pinned_count = sum(1 for p in report.pins if p.style == PinStyle.EXACT)
    report.compatible_pinned_count = sum(1 for p in report.pins if p.style == PinStyle.COMPATIBLE)
    report.minimum_pinned_count = sum(1 for p in report.pins if p.style == PinStyle.MINIMUM)
    report.range_pinned_count = sum(1 for p in report.pins if p.style == PinStyle.RANGE)
    report.unpinned_count = sum(1 for p in report.pins if p.is_unpinned)
    report.wildcard_count = sum(1 for p in report.pins if p.style == PinStyle.WILDCARD)

    # Calculate health score (0-100)
    # Components: pin coverage (50%), pin quality (30%), risk penalty (20%)
    coverage_score = report.pin_coverage * 0.5

    # Quality: exact and compatible pins are best
    quality_deps = report.exact_pinned_count + report.compatible_pinned_count
    quality_score = (quality_deps / max(report.total_dependencies, 1)) * 30

    # Risk penalty: average risk score lowers the score
    avg_risk = sum(p.risk_score for p in report.pins) / max(len(report.pins), 1)
    risk_penalty = min(avg_risk * 2.86, 20)  # Max 20 point penalty

    report.health_score = max(0, min(100, coverage_score + quality_score + 20 - risk_penalty))

    return report


# ── Constraint File Generation ───────────────────────────────────────────


def generate_constraints_file(report: PinReport) -> str:
    """Generate a pip constraints file from the pin report.

    Args:
        report: The pin report to generate constraints from.

    Returns:
        String content of a constraints file.
    """
    lines = [
        "# depcheck-generated constraints file",
        f"# Project: {report.project_path}",
        f"# Generated with depcheck pinpoint --generate-constraints",
        "",
    ]

    for pin in sorted(report.pins, key=lambda p: p.name):
        if pin.is_exact_pinned and pin.version:
            lines.append(f"{pin.name}=={pin.version}")
        elif pin.style == PinStyle.COMPATIBLE and pin.version:
            lines.append(f"{pin.name}~={pin.version}")
        elif pin.style == PinStyle.MINIMUM and pin.raw_specifier:
            lines.append(f"{pin.name}{pin.raw_specifier}")
        elif pin.style == PinStyle.RANGE and pin.raw_specifier:
            lines.append(f"{pin.name}{pin.raw_specifier}")
        elif pin.latest_version:
            # Unpinned: constrain to current latest
            lines.append(f"{pin.name}<={pin.latest_version}")
        else:
            lines.append(f"# {pin.name} — version unknown, consider pinning")

    return "\n".join(lines) + "\n"


# ── Rendering ────────────────────────────────────────────────────────────


def render_pin_table(report: PinReport, console: Console | None = None) -> None:
    """Render the pin report as a Rich table.

    Args:
        report: The pin report to render.
        console: Rich console to render to.
    """
    if console is None:
        console = Console()

    # Health score panel
    score_color = "green" if report.health_score >= 80 else "yellow" if report.health_score >= 60 else "red"
    summary = (
        f"[bold]Dependencies:[/bold] {report.total_dependencies}  "
        f"[bold]Pinned:[/bold] {report.pinned_count} ({report.pin_coverage:.0f}%)  "
        f"[bold]Unpinned:[/bold] {report.unpinned_count}  "
        f"[{score_color}]Health Score: {report.health_score:.0f}/100[/{score_color}]"
    )
    console.print(Panel(summary, title="Pinning Analysis", border_style=score_color))

    # Pin style breakdown
    breakdown = (
        f"  [green]== (exact):[/green] {report.exact_pinned_count}  "
        f"[cyan]~= (compatible):[/cyan] {report.compatible_pinned_count}  "
        f"[yellow]>= (minimum):[/yellow] {report.minimum_pinned_count}  "
        f"[blue]Range (>=,<):[/blue] {report.range_pinned_count}  "
        f"[magenta]* (wildcard):[/magenta] {report.wildcard_count}  "
        f"[red]Unpinned:[/red] {report.unpinned_count}"
    )
    console.print(breakdown)

    # Detailed table
    table = Table(title="Pinning Details", show_lines=True)
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Specifier", style="magenta")
    table.add_column("Style", style="green")
    table.add_column("Version", style="yellow")
    table.add_column("Latest", style="blue")
    table.add_column("Risk", justify="right")
    table.add_column("Recommendation", style="bold", max_width=40)

    for pin in sorted(report.pins, key=lambda p: -p.risk_score):
        risk_str = f"{pin.risk_score:.0f}/10"
        risk_color = "red" if pin.risk_score >= 7 else "yellow" if pin.risk_score >= 4 else "green"

        rec_str = ""
        if pin.recommendation != PinRecommendation.KEEP:
            rec_str = pin.rationale[:80] if pin.rationale else pin.recommendation.value

        table.add_row(
            pin.name,
            pin.raw_specifier or "—",
            pin.style.value,
            pin.version or "—",
            pin.latest_version or "—",
            f"[{risk_color}]{risk_str}[/{risk_color}]",
            rec_str,
        )

    console.print(table)

    # Recommendations
    if report.recommendations:
        console.print(f"\n[bold]📋 {len(report.recommendations)} pinning recommendations:[/bold]")
        for pin in report.recommendations[:10]:
            console.print(f"  • [cyan]{pin.name}[/cyan]: {pin.rationale}")
        if len(report.recommendations) > 10:
            console.print(f"  [dim]... and {len(report.recommendations) - 10} more[/dim]")


def render_pin_json(report: PinReport) -> str:
    """Render the pin report as JSON.

    Args:
        report: The pin report to render.

    Returns:
        JSON string of the pin report.
    """
    return json.dumps(report.to_dict(), indent=2)
