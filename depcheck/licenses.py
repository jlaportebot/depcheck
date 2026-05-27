"""License classification and compliance checking for depcheck."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class LicenseCategory(Enum):
    """Broad license categories for compliance checking."""

    PERMISSIVE = "permissive"
    COPYLEFT = "copyleft"
    PROPRIETARY = "proprietary"
    PUBLIC_DOMAIN = "public_domain"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


# Permissive licenses: allow use, modification, distribution with minimal restrictions
PERMISSIVE_IDS: frozenset[str] = frozenset({
    "MIT",
    "MIT License",
    "Apache-2.0",
    "Apache License 2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD License",
    "ISC",
    "ISC License",
    "PSF-2.0",
    "Python-2.0",
    "Python Software Foundation License",
    "0BSD",
    "BSD-1-Clause",
    "PostgreSQL",
    "X11",
    "MIT-0",
    "Apache-1.1",
    "Unlicense",
    "Zlib",
    "libpng-2.0",
    "BSL-1.0",
    "AFL-3.0",
    "AFL-2.1",
    "AFL-2.0",
    "Artistic-2.0",
    "Unicode-DFS-2016",
    "BlueOak-1.0.0",
    "NIST-PD",
    "NIST-PD-fallback",
})

# Copyleft licenses: require derivative works to use same license
COPYLEFT_IDS: frozenset[str] = frozenset({
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "LGPL-2.0",
    "LGPL-2.1",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-2.0",
    "MPL-1.1",
    "EUPL-1.2",
    "CPAL-1.0",
    "OSL-3.0",
    "OSL-2.1",
    "RPL-1.5",
    "RPL-1.1",
    "Sleepycat",
    "IPL-1.0",
    "CDDL-1.0",
    "CDDL-1.1",
    "EPL-1.0",
    "EPL-2.0",
    "CPL-1.0",
})

# Public domain licenses
PUBLIC_DOMAIN_IDS: frozenset[str] = frozenset({
    "CC0-1.0",
    "Unlicense",
    "CC-PDDC",
    "WTFPL",
})

# Restricted/proprietary licenses (no commercial use, etc.)
RESTRICTED_IDS: frozenset[str] = frozenset({
    "CC-BY-NC-1.0",
    "CC-BY-NC-2.0",
    "CC-BY-NC-2.5",
    "CC-BY-NC-3.0",
    "CC-BY-NC-4.0",
    "CC-BY-NC-ND-3.0",
    "CC-BY-NC-ND-4.0",
    "CC-BY-NC-SA-2.0",
    "CC-BY-NC-SA-3.0",
    "CC-BY-NC-SA-4.0",
    "NPOSL-3.0",
    "JSON License",
})

# License name aliases — maps common variations to canonical SPDX IDs
LICENSE_ALIASES: dict[str, str] = {
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "2-clause bsd": "BSD-2-Clause",
    "3-clause bsd": "BSD-3-Clause",
    "isc": "ISC",
    "isc license": "ISC",
    "gpl": "GPL-3.0",
    "gplv2": "GPL-2.0",
    "gplv3": "GPL-3.0",
    "gpl-2": "GPL-2.0",
    "gpl-3": "GPL-3.0",
    "gpl-2.0": "GPL-2.0",
    "gpl-3.0": "GPL-3.0",
    "gnu gpl v2": "GPL-2.0",
    "gnu gpl v3": "GPL-3.0",
    "gnu general public license v2": "GPL-2.0",
    "gnu general public license v3": "GPL-3.0",
    "gnu general public license v3 (gplv3)": "GPL-3.0",
    "gnu general public license v2 (gplv2)": "GPL-2.0",
    "gnu lesser general public license v2.1": "LGPL-2.1",
    "gnu lesser general public license v3": "LGPL-3.0",
    "gnu affero general public license v3": "AGPL-3.0",
    "mozilla public license 1.1": "MPL-1.1",
    "mozilla public license 2.0": "MPL-2.0",
    "lgpl": "LGPL-3.0",
    "lgplv2": "LGPL-2.1",
    "lgplv2.1": "LGPL-2.1",
    "lgplv3": "LGPL-3.0",
    "agpl": "AGPL-3.0",
    "agplv3": "AGPL-3.0",
    "agpl-3.0": "AGPL-3.0",
    "mpl": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "mpl-2.0": "MPL-2.0",
    "cc0": "CC0-1.0",
    "cc0-1.0": "CC0-1.0",
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "python": "Python-2.0",
    "psf": "PSF-2.0",
    "psf-2.0": "PSF-2.0",
    "python software foundation": "PSF-2.0",
    "zlib": "Zlib",
    "zlib license": "Zlib",
    "0bsd": "0BSD",
    "boost software license 1.0": "BSL-1.0",
    "bsl-1.0": "BSL-1.0",
}


def normalize_license_id(raw: str) -> str:
    """Normalize a license identifier to a canonical SPDX ID.

    Handles:
    - SPDX IDs (e.g., "MIT", "Apache-2.0")
    - Common name variations (e.g., "MIT License" → "MIT")
    - Case-insensitive matching
    - License expressions with AND/OR (takes first license)

    Args:
        raw: The raw license string from PyPI metadata.

    Returns:
        The normalized SPDX license ID, or the original string if unrecognized.
    """
    if not raw:
        return ""

    # Handle "UNKNOWN" or similar placeholders
    if raw.upper().strip() in ("UNKNOWN", "N/A", "NONE", "SEE LICENSE"):
        return ""

    # Take the first license in compound expressions (e.g., "MIT OR Apache-2.0")
    cleaned = raw.strip()
    for separator in (" OR ", " or ", " AND ", " and ", ";"):
        if separator in cleaned:
            parts = [p.strip() for p in cleaned.split(separator)]
            # For OR, prefer permissive if available
            if separator.strip().upper() == "OR":
                permissive = [
                p
                for p in parts
                if classify_license(normalize_single_id(p))
                == LicenseCategory.PERMISSIVE
            ]
                if permissive:
                    cleaned = permissive[0]
                else:
                    cleaned = parts[0]
            else:
                cleaned = parts[0]
            break

    # Remove surrounding parentheses
    cleaned = cleaned.strip("()\"'")

    return normalize_single_id(cleaned)


def normalize_single_id(raw: str) -> str:
    """Normalize a single license identifier (no compound expressions).

    Args:
        raw: A single license name or SPDX ID.

    Returns:
        The normalized SPDX license ID.
    """
    stripped = raw.strip().strip("+")

    # Check aliases first (case-insensitive) — handles Trove classifier names
    lower = stripped.lower()
    if lower in LICENSE_ALIASES:
        return LICENSE_ALIASES[lower]

    # Check if it's already a known SPDX ID
    if stripped in PERMISSIVE_IDS | COPYLEFT_IDS | PUBLIC_DOMAIN_IDS | RESTRICTED_IDS:
        return stripped

    return stripped


def classify_license(license_id: str) -> LicenseCategory:
    """Classify a license ID into a broad category.

    Args:
        license_id: A normalized SPDX license ID.

    Returns:
        The license category.
    """
    if not license_id:
        return LicenseCategory.UNKNOWN

    # Check PUBLIC_DOMAIN first (some IDs like Unlicense are in both sets)
    if license_id in PUBLIC_DOMAIN_IDS:
        return LicenseCategory.PUBLIC_DOMAIN
    if license_id in PERMISSIVE_IDS:
        return LicenseCategory.PERMISSIVE
    if license_id in COPYLEFT_IDS:
        return LicenseCategory.COPYLEFT
    if license_id in RESTRICTED_IDS:
        return LicenseCategory.RESTRICTED

    # Try case-insensitive matching for common patterns
    upper = license_id.upper()
    if any(x in upper for x in ("MIT", "BSD", "APACHE", "ISC", "PSF", "PYTHON")):
        return LicenseCategory.PERMISSIVE
    if any(x in upper for x in ("GPL", "AGPL", "LGPL", "MPL", "CDDL", "EPL", "CPL", "EUPL")):
        return LicenseCategory.COPYLEFT
    if any(x in upper for x in ("CC0", "UNLICENSE", "PUBLIC DOMAIN")):
        return LicenseCategory.PUBLIC_DOMAIN
    if any(x in upper for x in ("NON-COMMERCIAL", "NC", "PROPRIETARY", "COMMERCIAL")):
        return LicenseCategory.RESTRICTED

    return LicenseCategory.UNKNOWN


@dataclass
class LicenseInfo:
    """License information for a package."""

    spdx_id: str = ""
    raw_license: str = ""
    category: LicenseCategory = LicenseCategory.UNKNOWN
    is_compliant: bool = True
    compliance_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "spdx_id": self.spdx_id,
            "raw_license": self.raw_license,
            "category": self.category.value,
            "is_compliant": self.is_compliant,
            "compliance_note": self.compliance_note,
        }


def check_license_compliance(
    license_info: LicenseInfo,
    allowed_categories: list[LicenseCategory] | None = None,
    denied_licenses: list[str] | None = None,
) -> LicenseInfo:
    """Check if a package's license is compliant with the given policy.

    Args:
        license_info: The license info to check.
        allowed_categories: List of allowed license categories. If None, all are allowed.
        denied_licenses: List of specific SPDX IDs to deny (regardless of category).

    Returns:
        The same LicenseInfo with compliance fields updated.
    """
    if not license_info.spdx_id:
        license_info.is_compliant = False
        license_info.compliance_note = "License could not be determined"
        return license_info

    if denied_licenses and license_info.spdx_id in denied_licenses:
        license_info.is_compliant = False
        license_info.compliance_note = f"License {license_info.spdx_id} is explicitly denied"
        return license_info

    if allowed_categories is not None:
        if license_info.category not in allowed_categories:
            license_info.is_compliant = False
            license_info.compliance_note = (
                f"License category '{license_info.category.value}' not in allowed: "
                f"{', '.join(c.value for c in allowed_categories)}"
            )
            return license_info

    license_info.is_compliant = True
    license_info.compliance_note = ""
    return license_info


def parse_license_from_pypi(info: dict[str, Any]) -> LicenseInfo:
    """Extract and classify license information from PyPI package metadata.

    PyPI provides license info in multiple fields with varying reliability:
    1. info.classifiers — most reliable, uses SPDX-like Trove classifiers
    2. info.license_expression — SPDX expression (PEP 639, newer packages)
    3. info.license — free text, often ambiguous or "UNKNOWN"

    Args:
        info: The full PyPI JSON API response for a package.

    Returns:
        LicenseInfo with the best available license data.
    """
    package_info = info.get("info", {})

    # 1. Try classifiers (most reliable)
    classifiers = package_info.get("classifiers", [])
    license_classifiers = [
        c for c in classifiers if c.startswith("License ::")
    ]

    # Extract SPDX ID from Trove classifiers
    # Format: "License :: <Category> :: <Name>"
    # e.g., "License :: OSI Approved :: MIT License"
    for classifier in license_classifiers:
        parts = classifier.split(" :: ")
        if len(parts) >= 3:
            trove_name = parts[-1].strip()
            normalized = normalize_license_id(trove_name)
            if normalized and classify_license(normalized) != LicenseCategory.UNKNOWN:
                category = classify_license(normalized)
                return LicenseInfo(
                    spdx_id=normalized,
                    raw_license=classifier,
                    category=category,
                )

    # 2. Try license_expression (PEP 639, newer standard)
    license_expr = package_info.get("license_expression", "")
    if license_expr and license_expr.upper() != "NOASSERTION":
        normalized = normalize_license_id(license_expr)
        if normalized:
            category = classify_license(normalized)
            return LicenseInfo(
                spdx_id=normalized,
                raw_license=license_expr,
                category=category,
            )

    # 3. Fall back to info.license (free text, least reliable)
    raw_license = package_info.get("license", "") or ""
    if raw_license and raw_license.upper() not in ("UNKNOWN", "N/A", "SEE LICENSE", ""):
        normalized = normalize_license_id(raw_license)
        category = classify_license(normalized)
        return LicenseInfo(
            spdx_id=normalized or raw_license,
            raw_license=raw_license,
            category=category,
        )

    return LicenseInfo(
        spdx_id="",
        raw_license=raw_license or "UNKNOWN",
        category=LicenseCategory.UNKNOWN,
        is_compliant=False,
        compliance_note="License could not be determined",
    )


# ---------------------------------------------------------------------------
# License Policy & Compliance Reporting
# ---------------------------------------------------------------------------


@dataclass
class LicensePolicy:
    """Declarative allow/deny policy for license compliance.

    Combines category-based allow lists, specific ID deny lists,
    and category deny lists into a single check.

    Args:
        allowed_categories: If set, only these categories are allowed.
        denied_ids: Specific SPDX IDs to deny.
        denied_categories: Entire categories to deny (e.g., copyleft).
        default_allow: If True (default), unknown licenses are allowed.
            If False, unknown licenses are denied (strict mode).

    Usage::

        policy = LicensePolicy(
            allowed_categories={LicenseCategory.PERMISSIVE},
            denied_ids={"GPL-3.0"},
        )
        result = policy.check("MIT")
        assert result.is_compliant
    """

    allowed_categories: set[LicenseCategory] | None = None
    denied_ids: set[str] | None = None
    denied_categories: set[LicenseCategory] | None = None
    default_allow: bool = True

    def check(self, spdx_id: str) -> "_PolicyCheckResult":
        """Check a single SPDX ID against this policy.

        Args:
            spdx_id: The SPDX license identifier to check.

        Returns:
            _PolicyCheckResult with is_compliant and reason.
        """
        # 1. Denied IDs take highest priority
        if self.denied_ids and spdx_id in self.denied_ids:
            return _PolicyCheckResult(
                is_compliant=False,
                reason=f"License {spdx_id} is explicitly denied by policy",
            )

        # 2. Classify and check denied categories
        category = classify_license(spdx_id)

        if self.denied_categories and category in self.denied_categories:
            return _PolicyCheckResult(
                is_compliant=False,
                reason=(
                    f"License {spdx_id} ({category.value}) is in a denied "
                    f"category by policy"
                ),
            )

        # 3. Check allowed categories
        if self.allowed_categories is not None:
            if category not in self.allowed_categories:
                # Special case: unknown/uncategorized
                if category == LicenseCategory.UNKNOWN:
                    if not self.default_allow:
                        return _PolicyCheckResult(
                            is_compliant=False,
                            reason=(
                                f"License {spdx_id} is uncategorized and "
                                f"strict mode is enabled"
                            ),
                        )
                    # default_allow=True: let uncategorized through
                    # when allowed_categories is set but they have no
                    # UNKNOWN in the set — this is a design choice to
                    # avoid false positives on novel licenses
                else:
                    allowed = ", ".join(c.value for c in self.allowed_categories)
                    return _PolicyCheckResult(
                        is_compliant=False,
                        reason=(
                            f"License {spdx_id} ({category.value}) not in "
                            f"allowed categories: {allowed}"
                        ),
                    )

        # 4. Empty/missing license ID
        if not spdx_id or spdx_id.upper() in ("UNKNOWN", "NOASSERTION", ""):
            if not self.default_allow:
                return _PolicyCheckResult(
                    is_compliant=False,
                    reason="License could not be determined (strict mode)",
                )

        return _PolicyCheckResult(is_compliant=True, reason="")


@dataclass
class _PolicyCheckResult:
    """Internal result from a policy check."""

    is_compliant: bool
    reason: str = ""


@dataclass
class PackageComplianceEntry:
    """Compliance status for a single package.

    Attributes:
        name: Package name.
        version: Installed version.
        license_info: LicenseInfo for this package.
        is_compliant: Whether the package passes the policy.
        denial_reason: Why it's non-compliant (empty if compliant).
    """

    name: str
    version: str
    license_info: LicenseInfo
    is_compliant: bool = True
    denial_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result: dict[str, Any] = {
            "name": self.name,
            "version": self.version,
            "license": self.license_info.spdx_id or "UNKNOWN",
            "category": self.license_info.category.value,
            "is_compliant": self.is_compliant,
        }
        if not self.is_compliant:
            result["denial_reason"] = self.denial_reason
        return result


@dataclass
class ComplianceReport:
    """Aggregated license compliance report for a project.

    Attributes:
        packages: List of per-package compliance entries.
        total: Total number of packages.
        compliant_count: Number of compliant packages.
        non_compliant_count: Number of non-compliant packages.
        uncategorized_count: Number of packages with unknown licenses.
        policy: The policy used for checking.
    """

    packages: list[PackageComplianceEntry] = field(default_factory=list)
    total: int = 0
    compliant_count: int = 0
    non_compliant_count: int = 0
    uncategorized_count: int = 0
    policy: LicensePolicy | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total": self.total,
            "compliant": self.compliant_count,
            "non_compliant": self.non_compliant_count,
            "uncategorized": self.uncategorized_count,
            "packages": [p.to_dict() for p in self.packages],
        }


# ---------------------------------------------------------------------------
# Compliance report rendering
# ---------------------------------------------------------------------------


def render_compliance_json(report: ComplianceReport) -> None:
    """Render a compliance report as JSON to stdout.

    Args:
        report: The compliance report to render.
    """
    import json

    print(json.dumps(report.to_dict(), indent=2))


def render_compliance_table(
    report: ComplianceReport, *, console: Any = None
) -> None:
    """Render a compliance report as a Rich table.

    Args:
        report: The compliance report to render.
        console: Optional Rich Console instance.
    """
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    if console is None:
        console = Console()

    console.print()
    console.print(
        Panel(
            "[bold]depcheck license[/bold] — License Compliance Report",
            border_style="blue",
        )
    )

    # Package table
    table = Table(
        title="License Compliance",
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("Package", style="bold", min_width=20)
    table.add_column("Version", min_width=10)
    table.add_column("License", min_width=15)
    table.add_column("Category", min_width=12)
    table.add_column("Status", min_width=12)

    for entry in report.packages:
        lic = entry.license_info
        if entry.is_compliant:
            status = "[green]✓ Compliant[/green]"
        else:
            status = f"[red]✗ {entry.denial_reason}[/red]"

        category_style = {
            "permissive": "green",
            "copyleft": "yellow",
            "public_domain": "green",
            "proprietary": "red",
            "restricted": "red",
            "uncategorized": "dim",
            "unknown": "dim",
        }.get(lic.category.value, "white")

        table.add_row(
            entry.name,
            entry.version or "unknown",
            lic.spdx_id or "UNKNOWN",
            f"[{category_style}]{lic.category.value}[/{category_style}]",
            status,
        )

    console.print(table)

    # Summary
    console.print()
    parts = [f"[bold]Total:[/bold] {report.total}"]
    if report.compliant_count:
        parts.append(f"[green]✓ Compliant: {report.compliant_count}[/green]")
    if report.non_compliant_count:
        parts.append(f"[red]✗ Non-compliant: {report.non_compliant_count}[/red]")
    if report.uncategorized_count:
        parts.append(f"[dim]? Uncategorized: {report.uncategorized_count}[/dim]")

    border = "red" if report.non_compliant_count > 0 else "green"
    console.print(
        Panel("\n".join(parts), title="Summary", border_style=border)
    )
    console.print()
