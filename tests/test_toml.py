"""Tests for depcheck.toml — centralized TOML parsing."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from depcheck.toml import TomlParseError, load_toml, loads_toml


class TestLoadsToml:
    """Tests for loads_toml."""

    def test_simple_dict(self) -> None:
        text = 'name = "test"\nversion = "1.0.0"'
        result = loads_toml(text)
        assert result == {"name": "test", "version": "1.0.0"}

    def test_nested_table(self) -> None:
        text = """
[project]
name = "myproject"
version = "1.0.0"
dependencies = ["requests>=2.28", "flask==2.3.0"]
"""
        result = loads_toml(text)
        assert result["project"]["name"] == "myproject"
        assert result["project"]["dependencies"] == ["requests>=2.28", "flask==2.3.0"]

    def test_poetry_format(self) -> None:
        text = """
[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28"
flask = "2.3.0"
"""
        result = loads_toml(text)
        assert result["tool"]["poetry"]["dependencies"]["python"] == "^3.9"
        assert result["tool"]["poetry"]["dependencies"]["requests"] == "^2.28"

    def test_invalid_toml_raises(self) -> None:
        with pytest.raises(TomlParseError):
            loads_toml("invalid = toml [")

    def test_empty_string(self) -> None:
        result = loads_toml("")
        assert result == {}

    def test_error_contains_line_info(self) -> None:
        with pytest.raises(TomlParseError) as exc_info:
            loads_toml("valid = 1\ninvalid = [")
        assert "line" in str(exc_info.value).lower() or "row" in str(exc_info.value).lower()


class TestLoadToml:
    """Tests for load_toml (file-based)."""

    def test_load_valid_file(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write('[project]\nname = "test"\nversion = "1.0.0"\n')
            f.flush()
            result = load_toml(Path(f.name))
            assert result == {"project": {"name": "test", "version": "1.0.0"}}

    def test_nonexistent_file_raises(self) -> None:
        with pytest.raises(TomlParseError) as exc_info:
            load_toml(Path("/nonexistent/file.toml"))
        assert (
            "not found" in str(exc_info.value).lower()
            or "no such file" in str(exc_info.value).lower()
        )

    def test_invalid_file_raises_with_path(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("invalid = toml [")
            f.flush()
            with pytest.raises(TomlParseError) as exc_info:
                load_toml(Path(f.name))
            assert f.name in str(exc_info.value)

    def test_unicode_decode_error(self) -> None:
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".toml", delete=False) as f:
            f.write(b"\xff\xfe")  # Invalid UTF-8
            f.flush()
            with pytest.raises(TomlParseError):
                load_toml(Path(f.name))


class TestTomlParseError:
    """Tests for TomlParseError exception."""

    def test_is_value_error_subclass(self) -> None:
        assert issubclass(TomlParseError, ValueError)

    def test_can_be_caught_as_value_error(self) -> None:
        with pytest.raises(ValueError):
            raise TomlParseError("test error")
