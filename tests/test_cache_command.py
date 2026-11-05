"""Tests for the ``depcheck cache`` command group.

The cache command exposes the on-disk SQLite response cache that
:mod:`depcheck.cache` manages: ``stats`` reports what is stored, ``clear``
empties it, and ``path`` prints the location of the database.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from depcheck.cache import ResponseCache
from depcheck.commands.cache import command as cache_command


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    """Return an isolated cache directory."""
    directory = tmp_path / "cache"
    directory.mkdir()
    return directory


@pytest.fixture
def populated_cache(cache_dir: Path) -> ResponseCache:
    """Return a cache with one live entry and one expired entry."""
    cache = ResponseCache(cache_dir, enabled=True)
    cache.set("pypi", "requests", {"version": "2.32.0"}, ttl=3600)
    cache.set("osv", "stale", {"vulns": []}, ttl=-1)
    return cache


class TestCacheStats:
    """Tests for ``depcheck cache stats``."""

    def test_help_renders(self):
        result = CliRunner().invoke(cache_command, ["stats", "--help"])
        assert result.exit_code == 0
        assert "stats" in result.output

    def test_reports_entries_for_cache_directory(self, cache_dir: Path):
        cache = ResponseCache(cache_dir, enabled=True)
        cache.set("pypi", "requests", {"version": "2.32.0"}, ttl=3600)

        result = CliRunner().invoke(cache_command, ["stats", "--cache-dir", str(cache_dir)])

        assert result.exit_code == 0
        assert "requests" not in result.output
        assert "entries" in result.output.lower() or "Entries" in result.output

    def test_json_output_is_parseable(self, cache_dir: Path):
        cache = ResponseCache(cache_dir, enabled=True)
        cache.set("pypi", "requests", {"version": "2.32.0"}, ttl=3600)

        result = CliRunner().invoke(
            cache_command, ["stats", "--cache-dir", str(cache_dir), "--json"]
        )

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["entries"] == 1
        assert payload["path"].endswith("cache.sqlite3")

    def test_json_output_reports_expired_entries(self, cache_dir: Path):
        cache = ResponseCache(cache_dir, enabled=True)
        cache.set("osv", "stale", {"vulns": []}, ttl=-1)

        result = CliRunner().invoke(
            cache_command, ["stats", "--cache-dir", str(cache_dir), "--json"]
        )

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["entries"] == 1
        assert payload["expired_entries"] == 1


class TestCacheClear:
    """Tests for ``depcheck cache clear``."""

    def test_help_renders(self):
        result = CliRunner().invoke(cache_command, ["clear", "--help"])
        assert result.exit_code == 0

    def test_removes_every_entry(self, cache_dir: Path):
        cache = ResponseCache(cache_dir, enabled=True)
        cache.set("pypi", "requests", {"version": "2.32.0"}, ttl=3600)
        cache.set("pypi", "httpx", {"version": "0.28.0"}, ttl=3600)

        result = CliRunner().invoke(cache_command, ["clear", "--cache-dir", str(cache_dir)])

        assert result.exit_code == 0
        assert cache.stats().entries == 0

    def test_json_output_reports_removed_count(self, cache_dir: Path):
        cache = ResponseCache(cache_dir, enabled=True)
        cache.set("pypi", "requests", {"version": "2.32.0"}, ttl=3600)

        result = CliRunner().invoke(
            cache_command, ["clear", "--cache-dir", str(cache_dir), "--json"]
        )

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["removed"] == 1


class TestCachePath:
    """Tests for ``depcheck cache path``."""

    def test_help_renders(self):
        result = CliRunner().invoke(cache_command, ["path", "--help"])
        assert result.exit_code == 0

    def test_prints_database_path(self, cache_dir: Path):
        result = CliRunner().invoke(cache_command, ["path", "--cache-dir", str(cache_dir)])

        assert result.exit_code == 0
        assert str(cache_dir / "cache.sqlite3") in result.output

    def test_json_output_is_parseable(self, cache_dir: Path):
        result = CliRunner().invoke(
            cache_command, ["path", "--cache-dir", str(cache_dir), "--json"]
        )

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["path"].endswith("cache.sqlite3")


class TestCacheGroup:
    """Tests for the ``cache`` group itself."""

    def test_group_help_lists_subcommands(self):
        result = CliRunner().invoke(cache_command, ["--help"])
        assert result.exit_code == 0
        for name in ("clear", "stats", "path"):
            assert name in result.output
