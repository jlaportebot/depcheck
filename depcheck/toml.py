"""Centralized TOML parsing for depcheck.

Provides a single, well-tested TOML loader used across the codebase.
Replaces inline `import tomllib; tomllib.loads(...)` blocks with typed
error handling that includes file path and line context.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any


class TomlParseError(ValueError):
    """Raised when TOML parsing fails.

    Includes the file path (if applicable) and line/column context
    to make debugging configuration issues easier.
    """

    def __init__(
        self,
        message: str,
        path: str | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        self.path = path
        self.line = line
        self.column = column
        # Build a detailed message
        parts = []
        if path:
            parts.append(f"in {path}")
        if line is not None:
            parts.append(f"line {line}")
            if column is not None:
                parts[-1] += f", column {column}"
        context = f" ({', '.join(parts)})" if parts else ""
        super().__init__(f"TOML parse error{context}: {message}")


def loads_toml(text: str, path: str | None = None) -> dict[str, Any]:
    """Parse a TOML string into a dictionary.

    Args:
        text: TOML content as a string.
        path: Optional file path for error context.

    Returns:
        Parsed TOML as a dictionary.

    Raises:
        TomlParseError: If the TOML is invalid, with line/column context.
    """
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        # tomllib.TOMLDecodeError has lineno and colno attributes in Python 3.11+
        line = getattr(e, "lineno", None)
        column = getattr(e, "colno", None)
        raise TomlParseError(str(e), path=path, line=line, column=column) from e


def load_toml(path: Path) -> dict[str, Any]:
    """Load and parse a TOML file.

    Args:
        path: Path to the TOML file.

    Returns:
        Parsed TOML as a dictionary.

    Raises:
        TomlParseError: If the file doesn't exist, can't be read, or contains invalid TOML.
    """
    if not path.exists():
        raise TomlParseError(f"File not found: {path}", path=str(path))

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        raise TomlParseError(f"File is not valid UTF-8: {e}", path=str(path)) from e
    except OSError as e:
        raise TomlParseError(f"Cannot read file: {e}", path=str(path)) from e

    try:
        return loads_toml(text, path=str(path))
    except TomlParseError:
        # Re-raise with path context
        raise
    except Exception as e:
        raise TomlParseError(f"Unexpected error parsing TOML: {e}", path=str(path)) from e
