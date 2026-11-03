"""Shared helpers for the depcheck command modules.

Every command lives in its own module under :mod:`depcheck.commands`. This
module holds the pieces they all need so the command modules stay small and
focused on presentation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from depcheck.models import ScanResult

__all__ = ["scan_project"]


def scan_project(*args: Any, **kwargs: Any) -> ScanResult:
    """Run a dependency scan through the CLI's scanner binding.

    The scanner is resolved from :mod:`depcheck.cli` at call time rather than
    imported directly. That keeps ``@patch("depcheck.cli.scan_project")``
    effective for every command in the tree, and keeps the import graph free
    of cycles between the CLI group and the command modules.

    Args:
        *args: Positional arguments forwarded to ``depcheck.scanner.scan_project``.
        **kwargs: Keyword arguments forwarded to ``depcheck.scanner.scan_project``.

    Returns:
        The scan result produced by the scanner.
    """
    from depcheck import cli

    return cli.scan_project(*args, **kwargs)
