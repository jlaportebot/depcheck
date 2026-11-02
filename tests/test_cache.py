"""Tests for the persistent response cache."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from depcheck import cache as cache_module
from depcheck.cache import ResponseCache, cache_database_path, cache_directory


@pytest.fixture(autouse=True)
def _reset_global_cache():
    cache_module.reset_cache()
    yield
    cache_module.reset_cache()


class TestCacheDirectory:
    """Tests for cache directory resolution."""

    def test_env_override_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(cache_module.CACHE_DIR_ENV, str(tmp_path / "custom"))
        assert cache_directory() == tmp_path / "custom"

    def test_xdg_cache_home_is_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(cache_module.CACHE_DIR_ENV, raising=False)
        monkeypatch.setenv("XDG_CACHE_HOME", "/tmp/xdg-cache")
        assert cache_directory() == Path("/tmp/xdg-cache") / cache_module.CACHE_DIR_NAME

    def test_database_path_uses_directory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(cache_module.CACHE_DIR_ENV, "/tmp/depcheck-cache")
        assert cache_database_path() == Path("/tmp/depcheck-cache") / cache_module.CACHE_DB_NAME


class TestResponseCache:
    """Tests for the ResponseCache class."""

    def test_set_then_get_roundtrip(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set("pypi", "requests", {"info": {"version": "2.31.0"}}, ttl=60)
        assert cache.get("pypi", "requests") == {"info": {"version": "2.31.0"}}
        cache.close()

    def test_get_missing_returns_none(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        assert cache.get("pypi", "missing") is None
        cache.close()

    def test_expired_entry_is_not_returned(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set("pypi", "requests", {"version": "1"}, ttl=1)
        assert cache.get("pypi", "requests") is not None
        time.sleep(1.1)
        assert cache.get("pypi", "requests") is None
        cache.close()

    def test_zero_ttl_is_not_stored(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set("pypi", "requests", {"version": "1"}, ttl=0)
        assert cache.get("pypi", "requests") is None
        cache.close()

    def test_disabled_cache_stores_nothing(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path, enabled=False)
        cache.set("pypi", "requests", {"version": "1"}, ttl=60)
        assert cache.get("pypi", "requests") is None
        cache.close()

    def test_namespace_isolation(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set("pypi", "requests", {"source": "pypi"}, ttl=60)
        cache.set("osv", "requests", {"source": "osv"}, ttl=60)
        assert cache.get("pypi", "requests") == {"source": "pypi"}
        assert cache.get("osv", "requests") == {"source": "osv"}
        cache.close()

    def test_delete_removes_entry(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set("pypi", "requests", {"version": "1"}, ttl=60)
        cache.delete("pypi", "requests")
        assert cache.get("pypi", "requests") is None
        cache.close()

    def test_clear_removes_everything(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set("pypi", "a", {"v": 1}, ttl=60)
        cache.set("pypi", "b", {"v": 2}, ttl=60)
        assert cache.clear() == 2
        assert cache.get("pypi", "a") is None
        cache.close()

    def test_stats_reports_entries(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set("pypi", "a", {"v": 1}, ttl=60)
        cache.set("pypi", "b", {"v": 2}, ttl=1)
        stats = cache.stats()
        assert stats.entries == 2
        assert stats.path.endswith(cache_module.CACHE_DB_NAME)
        assert stats.size_bytes > 0
        cache.close()

    def test_stats_counts_expired_entries(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set("pypi", "a", {"v": 1}, ttl=1)
        time.sleep(1.1)
        stats = cache.stats()
        assert stats.expired_entries == 1
        cache.close()

    def test_database_file_is_created(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set("pypi", "a", {"v": 1}, ttl=60)
        assert cache.path.exists()
        cache.close()

    def test_corrupt_value_is_treated_as_missing(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set("pypi", "a", {"v": 1}, ttl=60)
        connection = cache._connect()
        key = cache.make_key("pypi", "a")
        connection.execute("UPDATE entries SET value = ? WHERE key = ?", ("{not json", key))
        assert cache.get("pypi", "a") is None
        cache.close()

    def test_non_dict_payload_is_not_returned(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set("pypi", "a", {"v": 1}, ttl=60)
        connection = cache._connect()
        key = cache.make_key("pypi", "a")
        connection.execute("UPDATE entries SET value = ? WHERE key = ?", ("[1,2,3]", key))
        assert cache.get("pypi", "a") is None
        cache.close()

    def test_key_is_stable_and_namespaced(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        first = cache.make_key("pypi", "requests")
        assert first == cache.make_key("pypi", "requests")
        assert first != cache.make_key("osv", "requests")
        cache.close()

    def test_persists_across_instances(self, tmp_path: Path) -> None:
        first = ResponseCache(tmp_path)
        first.set("pypi", "requests", {"version": "2.31.0"}, ttl=60)
        first.close()

        second = ResponseCache(tmp_path)
        assert second.get("pypi", "requests") == {"version": "2.31.0"}
        second.close()

    def test_unserializable_payload_is_ignored(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set("pypi", "a", {"obj": object()}, ttl=60)
        assert cache.get("pypi", "a") is None
        cache.close()


class TestCacheConfiguration:
    """Tests for the process-wide cache configuration."""

    def test_get_cache_returns_singleton(self) -> None:
        assert cache_module.get_cache() is cache_module.get_cache()

    def test_configure_cache_replaces_instance(self, tmp_path: Path) -> None:
        first = cache_module.get_cache()
        second = cache_module.configure_cache(directory=tmp_path, enabled=True)
        assert second is not first
        assert second.path.parent == tmp_path

    def test_configure_cache_can_disable(self, tmp_path: Path) -> None:
        cache = cache_module.configure_cache(directory=tmp_path, enabled=False)
        assert cache.enabled is False

    def test_configure_cache_offline_flag(self, tmp_path: Path) -> None:
        cache = cache_module.configure_cache(directory=tmp_path, offline=True)
        assert cache.offline is True

    def test_no_cache_env_disables_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(cache_module.CACHE_DISABLE_ENV, "1")
        cache = ResponseCache(tmp_path)
        assert cache.enabled is False
        cache.close()

    def test_env_flag_accepts_common_truthy_values(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for value in ("1", "true", "YES", "on"):
            monkeypatch.setenv(cache_module.CACHE_DISABLE_ENV, value)
            cache = ResponseCache(tmp_path)
            assert cache.enabled is False
            cache.close()


class TestCacheFileFormat:
    """Tests for the on-disk representation."""

    def test_stored_value_is_json(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set("pypi", "a", {"v": [1, 2]}, ttl=60)
        connection = cache._connect()
        row = connection.execute("SELECT value FROM entries").fetchone()
        assert json.loads(row[0]) == {"v": [1, 2]}
        cache.close()

    def test_database_uses_wal_mode(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set("pypi", "a", {"v": 1}, ttl=60)
        mode = cache._connect().execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
        cache.close()

    def test_no_environment_leakage_between_tests(self) -> None:
        assert os.environ.get(cache_module.CACHE_DISABLE_ENV) is None
