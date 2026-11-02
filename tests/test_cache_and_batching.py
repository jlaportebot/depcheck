"""Tests for the offline cache, batch fetching and concurrent scans."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depcheck.cache import OfflineCacheMissError, ResponseCache, configure_cache
from depcheck.models import ParsedDependency
from depcheck.osv import OSVClient
from depcheck.pypi import CACHE_NAMESPACE as PYPI_NAMESPACE
from depcheck.pypi import PyPIClient
from depcheck.scanner import scan_dependencies


def _dep(name: str, version: str | None = None) -> ParsedDependency:
    return ParsedDependency(name=name, version=version)


class TestOfflineMode:
    """Offline mode must never touch the network."""

    def test_pypi_cache_miss_raises_offline_error(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path, offline=True)
        client = PyPIClient(cache=cache)
        with pytest.raises(OfflineCacheMissError) as excinfo:
            client.get_package_info("requests")
        assert "requests" in str(excinfo.value)
        client.close()
        cache.close()

    def test_pypi_cache_hit_is_served_offline(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set(PYPI_NAMESPACE, "requests", {"info": {"version": "2.31.0"}}, ttl=60)
        offline_cache = ResponseCache(tmp_path, offline=True)
        client = PyPIClient(cache=offline_cache)
        with patch("depcheck.pypi.httpx.Client") as mock_client_cls:
            client.get_package_info("requests")
            mock_client_cls.assert_not_called()
        client.close()
        offline_cache.close()
        cache.close()

    def test_osv_cache_miss_raises_offline_error(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path, offline=True)
        client = OSVClient(cache=cache)
        with pytest.raises(OfflineCacheMissError):
            client.query_vulnerabilities("requests", "2.31.0")
        client.close()
        cache.close()

    def test_offline_env_var_enables_offline(self, tmp_path: Path, monkeypatch) -> None:
        from depcheck import cache as cache_module

        monkeypatch.setenv(cache_module.OFFLINE_ENV, "1")
        cache_module.reset_cache()
        cache = cache_module.get_cache()
        assert cache.offline is True
        cache_module.reset_cache()


class TestBatchFetching:
    """Batch endpoints must collapse many lookups into few requests."""

    def test_pypi_many_uses_one_request_per_package(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        client = PyPIClient(cache=cache)
        mock_client = MagicMock()
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"info": {"version": "1.0"}}
        mock_client.get.return_value = response
        client._client = mock_client

        results = client.get_package_info_many(["a", "b", "c"])

        assert set(results) == {"a", "b", "c"}
        assert mock_client.get.call_count == 3
        client.close()
        cache.close()

    def test_pypi_many_uses_cache_before_network(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        cache.set(PYPI_NAMESPACE, "a", {"info": {"version": "1.0"}}, ttl=60)
        client = PyPIClient(cache=cache)
        mock_client = MagicMock()
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"info": {"version": "2.0"}}
        mock_client.get.return_value = response
        client._client = mock_client

        results = client.get_package_info_many(["a", "b"])

        assert results["a"] == {"info": {"version": "1.0"}}
        assert mock_client.get.call_count == 1
        client.close()
        cache.close()

    def test_osv_batch_sends_one_request(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        client = OSVClient(cache=cache)
        mock_client = MagicMock()
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "results": [{"vulns": []}, {"vulns": []}, {"vulns": []}],
        }
        mock_client.post.return_value = response
        client._client = mock_client

        results = client.query_vulnerabilities_batch([("a", "1.0"), ("b", "2.0"), ("c", "3.0")])

        assert len(results) == 3
        assert mock_client.post.call_count == 1
        client.close()
        cache.close()

    def test_osv_batch_chunks_large_payloads(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        client = OSVClient(cache=cache)
        mock_client = MagicMock()
        response = MagicMock()
        response.status_code = 200
        response.json.side_effect = lambda: {"results": [{"vulns": []} for _ in range(1000)]}
        mock_client.post.return_value = response
        client._client = mock_client

        packages = [(f"pkg{index}", "1.0") for index in range(1500)]
        results = client.query_vulnerabilities_batch(packages)

        assert len(results) == 1500
        assert mock_client.post.call_count == 2
        client.close()
        cache.close()


class TestScanDependencies:
    """The batched scanner must produce the same reports as the old loop."""

    def test_scan_dependencies_uses_batch_endpoints(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        pypi = PyPIClient(cache=cache)
        osv = OSVClient(cache=cache)

        mock_pypi = MagicMock()
        pypi_response = MagicMock()
        pypi_response.status_code = 200
        pypi_response.json.return_value = {
            "info": {"version": "2.0.0"},
            "releases": {
                "2.0.0": [{"upload_time_iso_8601": "2026-11-01T00:00:00Z"}],
            },
        }
        mock_pypi.get.return_value = pypi_response
        pypi._client = mock_pypi

        mock_osv = MagicMock()
        osv_response = MagicMock()
        osv_response.status_code = 200
        osv_response.json.return_value = {"results": [{"vulns": []}]}
        mock_osv.post.return_value = osv_response
        osv._client = mock_osv

        reports = scan_dependencies(
            [_dep("alpha", "1.0"), _dep("beta", "2.0")],
            pypi_client=pypi,
            osv_client=osv,
        )

        assert [report.name for report in reports] == ["alpha", "beta"]
        assert mock_osv.post.call_count == 1
        pypi.close()
        osv.close()
        cache.close()

    def test_scan_dependencies_reports_removed_package(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path)
        pypi = PyPIClient(cache=cache)
        osv = OSVClient(cache=cache)

        mock_pypi = MagicMock()
        response = MagicMock()
        response.status_code = 404
        mock_pypi.get.return_value = response
        pypi._client = mock_pypi

        reports = scan_dependencies(
            [_dep("gone")],
            pypi_client=pypi,
            osv_client=osv,
        )

        assert reports[0].is_removed is True
        pypi.close()
        osv.close()
        cache.close()

    def test_scan_dependencies_handles_empty_input(self) -> None:
        assert scan_dependencies([]) == []


class TestCacheTtlOverrides:
    """TTL overrides must be honoured per namespace."""

    def test_ttl_override_is_used(self, tmp_path: Path) -> None:
        cache = ResponseCache(tmp_path, ttl_overrides={"pypi": 42})
        assert cache.ttl_for("pypi", 3600) == 42
        assert cache.ttl_for("osv", 3600) == 3600
        cache.close()

    def test_configure_cache_reads_ttl_env(self, tmp_path: Path, monkeypatch) -> None:
        from depcheck import cache as cache_module

        monkeypatch.setenv(cache_module.CACHE_TTL_ENV, "120")
        cache = configure_cache(directory=tmp_path, enabled=True)
        assert cache.ttl_for("pypi", 3600) == 120
        cache.close()


class TestCacheThreadSafety:
    """The cache must be usable from the worker pool."""

    def test_concurrent_writes_are_safe(self, tmp_path: Path) -> None:
        from concurrent.futures import ThreadPoolExecutor

        cache = ResponseCache(tmp_path)

        def write(index: int) -> None:
            cache.set(PYPI_NAMESPACE, f"pkg{index}", {"v": index}, ttl=60)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(write, range(50)))

        assert cache.stats().entries == 50
        cache.close()


class TestCliCacheFlags:
    """The global cache flags must be wired to the CLI."""

    def test_offline_flag_is_registered(self) -> None:
        from click.testing import CliRunner

        from depcheck.cli import main

        result = CliRunner().invoke(main, ["--help"])
        assert "--offline" in result.output
        assert "--no-cache" in result.output

    def test_no_cache_flag_disables_cache(self) -> None:
        from click.testing import CliRunner

        from depcheck.cli import main

        result = CliRunner().invoke(main, ["--no-cache", "--help"])
        assert result.exit_code == 0

    def test_cache_ttl_zero_disables_cache(self) -> None:
        from click.testing import CliRunner

        from depcheck.cli import main

        result = CliRunner().invoke(main, ["--cache-ttl", "0", "--help"])
        assert result.exit_code == 0


class TestJsonOutStillValid:
    """The canonical JSON helper must keep emitting parseable documents."""

    def test_long_string_survives_json_emission(self) -> None:
        from depcheck import jsonout

        payload = {"path": "x" * 400}
        document = jsonout.to_json(payload)
        assert json.loads(document) == payload
