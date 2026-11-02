"""Package name normalization utilities (PEP 503).

Single home for package name canonicalization used across depcheck.
"""

from __future__ import annotations

import re

# PEP 503 normalization: lowercase, replace runs of [-_.] with single hyphen
_PEP503_REGEX = re.compile(r"[-_.]+")


def normalize_package_name(name: str) -> str:
    """Normalize a package name per PEP 503.

    Args:
        name: Package name to normalize.

    Returns:
        Normalized name (lowercase, runs of [-_.] replaced with single hyphen).
    """
    if not name:
        return ""
    return _PEP503_REGEX.sub("-", name).lower()


# Alias for distribution name normalization (same as package name per PEP 503)
normalize_dist_name = normalize_package_name


def canonicalize(name: str) -> str:
    """Canonicalize a package specification by stripping extras and markers.

    This extracts just the package name from a requirement string like
    "requests[security]>=2.28; python_version>='3.8'" -> "requests"

    Args:
        name: A requirement string possibly containing extras [..] and/or markers ;...

    Returns:
        Normalized package name only (no version specifier, extras, or markers).
    """
    if not name:
        return ""

    # Strip extras: [extra1,extra2]
    name = re.sub(r"\[.*?\]", "", name)

    # Strip environment markers: ; marker_expression
    name = re.sub(r"\s*;.*$", "", name)

    # Strip version specifiers: >=1.0, ==2.0, etc.
    name = re.sub(r"\s*[<>=!~].*$", "", name)

    # Normalize the remaining package name
    return normalize_package_name(name.strip())
