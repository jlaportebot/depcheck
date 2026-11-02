"""Canonical JSON emission for depcheck.

Every ``--json`` code path in depcheck must write machine-readable JSON that
survives ``json.loads()`` untouched. Rich's :class:`~rich.console.Console`
soft-wraps printed text at the terminal width and injects hard newlines inside
long strings, which corrupts JSON payloads. Rich's own markup, highlighting and
emoji replacement can also mangle JSON string values.

The helpers below print JSON through Rich with every content-mangling feature
disabled, so the emitted document is exactly what was serialized while still
honouring the console abstraction (including ``Console.capture()``).
"""

from __future__ import annotations

import json
import sys
from typing import Any

from rich.console import Console

#: Default indentation used for every JSON payload depcheck emits.
JSON_INDENT = 2


def dumps(payload: Any, **kwargs: Any) -> str:
    """Serialize a payload to JSON using depcheck's canonical settings.

    Args:
        payload: The object to serialize.
        **kwargs: Extra arguments forwarded to :func:`json.dumps`.

    Returns:
        The serialized JSON document.
    """
    kwargs.setdefault("indent", JSON_INDENT)
    kwargs.setdefault("default", str)
    return json.dumps(payload, **kwargs)


def _safe_console(console: Console | None) -> Console:
    """Return a console that cannot reinterpret or re-wrap JSON content.

    Args:
        console: The caller-provided console, or None to build a plain one.

    Returns:
        A console configured to emit the payload verbatim.
    """
    if console is None:
        return Console(force_terminal=False, no_color=True)
    return console


def _print_document(console: Console, document: str) -> None:
    """Print a serialized document without wrapping or re-interpretation.

    Args:
        console: The console that receives the document.
        document: The already-serialized text to print.
    """
    console.print(
        document,
        soft_wrap=True,
        markup=False,
        highlight=False,
        emoji=False,
    )


def write_json(payload: Any, console: Console | None = None, **kwargs: Any) -> None:
    """Write a JSON payload to the console without corrupting it.

    Args:
        payload: The object to serialize.
        console: Optional Rich console that receives the document. When omitted
            the document is written to stdout.
        **kwargs: Extra arguments forwarded to :func:`json.dumps`.
    """
    _print_document(_safe_console(console), dumps(payload, **kwargs))


def write_text(document: str, console: Console | None = None) -> None:
    """Write a pre-serialized document to the console without corrupting it.

    Args:
        document: The already-serialized text to write.
        console: Optional Rich console that receives the document. When omitted
            the document is written to stdout.
    """
    _print_document(_safe_console(console), document)


def to_json(payload: Any, **kwargs: Any) -> str:
    """Return a JSON document for a payload using depcheck's canonical settings.

    Args:
        payload: The object to serialize.
        **kwargs: Extra arguments forwarded to :func:`json.dumps`.

    Returns:
        The serialized JSON document.
    """
    return dumps(payload, **kwargs)


def write_to_stdout(document: str) -> None:
    """Write a pre-serialized document straight to stdout.

    Args:
        document: The already-serialized text to write.
    """
    sys.stdout.write(document + "\n")
    sys.stdout.flush()
