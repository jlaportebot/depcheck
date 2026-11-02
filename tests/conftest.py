"""Shared pytest fixtures for the depcheck test suite.

Every test runs against an isolated cache directory so that cached responses
never leak between tests (or between a developer's local runs and CI).
"""

from __future__ import annotations

import pytest

from depcheck import cache as cache_module


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch):
    """Point the response cache at a per-test directory and reset global state.

    Yields:
        The temporary directory that holds the cache database.
    """
    cache_dir = tmp_path_factory.mktemp("depcheck-cache")
    monkeypatch.setenv(cache_module.CACHE_DIR_ENV, str(cache_dir))
    monkeypatch.delenv(cache_module.OFFLINE_ENV, raising=False)
    monkeypatch.delenv(cache_module.CACHE_TTL_ENV, raising=False)
    cache_module.reset_cache()
    yield cache_dir
    cache_module.reset_cache()
