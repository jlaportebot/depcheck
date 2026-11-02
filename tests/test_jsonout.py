"""Regression tests for canonical JSON output.

Every ``--json`` code path must emit a document that survives ``json.loads()``
untouched. Rich's Console soft-wraps printed text at the terminal width and
injects hard newlines inside long strings, which used to corrupt JSON payloads
(e.g. ``depcheck diff --json`` on long paths raised
``Invalid control character``). Rich's markup/highlight/emoji handling can also
mangle JSON string values.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console

from depcheck import jsonout
from depcheck.cli import main

# ---------------------------------------------------------------------------
# jsonout unit tests
# ---------------------------------------------------------------------------


class TestDumps:
    """Tests for jsonout.dumps."""

    def test_uses_two_space_indent_by_default(self) -> None:
        document = jsonout.dumps({"a": 1})
        assert document == '{\n  "a": 1\n}'

    def test_serializes_unserializable_values_as_strings(self) -> None:
        document = jsonout.dumps({"path": Path("/tmp/example")})
        assert "/tmp/example" in document

    def test_kwargs_override_defaults(self) -> None:
        document = jsonout.dumps({"a": 1}, indent=4)
        assert '\n    "a": 1' in document

    def test_to_json_matches_dumps(self) -> None:
        payload = {"nested": {"value": [1, 2, 3]}}
        assert jsonout.to_json(payload) == jsonout.dumps(payload)


class TestWriteJson:
    """Tests for jsonout.write_json."""

    def test_writes_to_console_file_without_wrapping(self) -> None:
        buffer = StringIO()
        console = Console(file=buffer, width=20, force_terminal=False, no_color=True)
        long_value = "x" * 300
        jsonout.write_json({"path": long_value}, console=console)
        document = buffer.getvalue()
        value_line = next(line for line in document.splitlines() if long_value in line)
        assert value_line.strip() == f'"path": "{long_value}"'
        assert json.loads(document)["path"] == long_value

    def test_writes_to_stdout_when_no_console(self, capsys: pytest.CaptureFixture[str]) -> None:
        jsonout.write_json({"value": 42})
        captured = capsys.readouterr()
        assert json.loads(captured.out) == {"value": 42}

    def test_output_is_valid_json_with_newline_terminator(self) -> None:
        buffer = StringIO()
        console = Console(file=buffer, width=200, force_terminal=False, no_color=True)
        jsonout.write_json({"value": 1}, console=console)
        assert buffer.getvalue().endswith("\n")

    def test_console_capture_receives_valid_json(self) -> None:
        console = Console(force_terminal=False, no_color=True, width=10000)
        with console.capture() as capture:
            jsonout.write_json({"value": 7}, console=console)
        assert json.loads(capture.get()) == {"value": 7}

    def test_rich_markup_in_values_is_not_interpreted(self) -> None:
        buffer = StringIO()
        console = Console(file=buffer, width=200, force_terminal=False, no_color=True)
        jsonout.write_json({"text": "literal [bracket] and *stars*"}, console=console)
        assert json.loads(buffer.getvalue())["text"] == "literal [bracket] and *stars*"

    def test_emoji_in_values_is_not_replaced(self) -> None:
        buffer = StringIO()
        console = Console(file=buffer, width=200, force_terminal=False, no_color=True)
        jsonout.write_json({"text": "release \U0001f389"}, console=console)
        assert json.loads(buffer.getvalue())["text"] == "release \U0001f389"

    def test_long_payload_survives_narrow_console(self) -> None:
        buffer = StringIO()
        console = Console(file=buffer, width=80, force_terminal=False, no_color=True)
        payload = {"path": "x" * 300, "items": ["a" * 120, "b" * 120]}
        jsonout.write_json(payload, console=console)
        assert json.loads(buffer.getvalue()) == payload


class TestWriteText:
    """Tests for jsonout.write_text."""

    def test_writes_pre_serialized_document(self) -> None:
        buffer = StringIO()
        console = Console(file=buffer, width=80, force_terminal=False, no_color=True)
        jsonout.write_text('{"a": 1}', console=console)
        assert json.loads(buffer.getvalue()) == {"a": 1}

    def test_write_to_stdout_helper(self, capsys: pytest.CaptureFixture[str]) -> None:
        jsonout.write_to_stdout('{"a": 1}')
        assert json.loads(capsys.readouterr().out) == {"a": 1}


# ---------------------------------------------------------------------------
# CLI-level regression: long paths must not corrupt JSON
# ---------------------------------------------------------------------------


LONG_PATH_SEGMENT = "a" * 120
LONG_PACKAGE_NAME = "some-extremely-long-package-name-that-should-not-be-wrapped"


class TestCliJsonIntegrity:
    """CLI JSON output must always be parseable."""

    def test_diff_json_with_long_paths_is_valid_json(self, tmp_path: Path) -> None:
        old_file = tmp_path / LONG_PATH_SEGMENT
        new_file = tmp_path / (LONG_PATH_SEGMENT + "-new")
        old_file.write_text(f"{LONG_PACKAGE_NAME}==2.28.0\n", encoding="utf-8")
        new_file.write_text(f"{LONG_PACKAGE_NAME}==2.31.0\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(main, ["diff", "--json", str(old_file), str(new_file)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["changed"] >= 1

    def test_diff_json_payload_contains_unwrapped_path(self, tmp_path: Path) -> None:
        old_file = tmp_path / LONG_PATH_SEGMENT
        new_file = tmp_path / (LONG_PATH_SEGMENT + "-new")
        old_file.write_text("requests==2.28.0\n", encoding="utf-8")
        new_file.write_text("requests==2.31.0\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(main, ["diff", "--json", str(old_file), str(new_file)])

        assert result.exit_code == 0
        assert str(old_file) in result.output

    def test_scan_json_output_is_valid_json(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--json", "--no-vuln-check", str(tmp_path)])

        assert result.exit_code in (0, 1)
        json.loads(result.output)
