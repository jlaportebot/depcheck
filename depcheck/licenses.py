"""License classification and compliance checking for depcheck."""

from __future__ import annotations

from dataclasses import dataclass
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
