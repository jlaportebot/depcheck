"""Persistent on-disk cache for network responses.

Every depcheck scan talks to PyPI and OSV. Those responses change slowly, so
caching them turns a cold scan (two HTTP round-trips per package) into a warm
scan with zero network traffic.

The cache is a single SQLite database in WAL mode, keyed by an opaque string.
Entries carry a TTL so stale data can never be served, and writes are atomic so
a killed process cannot corrupt the database.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Default cache directory name under the user's cache root.
CACHE_DIR_NAME = "depcheck"

#: Default database filename inside the cache directory.
CACHE_DB_NAME = "cache.sqlite3"

#: Default TTL for PyPI metadata responses (seconds).
PYPI_TTL_SECONDS = 3600

#: Default TTL for OSV vulnerability responses (seconds).
OSV_TTL_SECONDS = 21600

#: Default TTL for anything else (seconds).
DEFAULT_TTL_SECONDS = 3600

#: Environment variable that overrides the cache directory.
CACHE_DIR_ENV = "DEPCHECK_CACHE_DIR"

#: Environment variable that disables the cache when set to a truthy value.
CACHE_DISABLE_ENV = "DEPCHECK_NO_CACHE"

#: Environment variable that forces offline (cache-only) operation.
OFFLINE_ENV = "DEPCHECK_OFFLINE"

#: Environment variable that overrides the default TTL for every namespace.
CACHE_TTL_ENV = "DEPCHECK_CACHE_TTL"


def cache_directory() -> Path:
    """Return the directory that holds the cache database.

    Returns:
        The resolved cache directory path.
    """
    override = os.environ.get(CACHE_DIR_ENV)
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".cache"
    return root / CACHE_DIR_NAME


def cache_database_path() -> Path:
    """Return the path of the cache database file.

    Returns:
        The resolved database path.
    """
    return cache_directory() / CACHE_DB_NAME


def _env_int(name: str) -> int | None:
    """Return an integer environment variable, or None when unset/invalid.

    Args:
        name: The environment variable name.

    Returns:
        The parsed integer value, or None.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def _ttl_overrides_from_env() -> dict[str, int]:
    """Build per-namespace TTL overrides from the environment.

    Returns:
        A mapping of namespace to TTL in seconds.
    """
    ttl = _env_int(CACHE_TTL_ENV)
    if ttl is None:
        return {}
    return {"pypi": ttl, "osv": ttl}


def _env_flag(name: str) -> bool:
    """Return whether an environment variable holds a truthy value.

    Args:
        name: The environment variable name.

    Returns:
        True when the variable is set to a truthy value.
    """
    value = os.environ.get(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


class OfflineCacheMissError(RuntimeError):
    """Raised when an offline run needs data that is not in the cache."""

    def __init__(self, namespace: str, identifier: str) -> None:
        """Initialize the error.

        Args:
            namespace: The API or subsystem the entry belongs to.
            identifier: The resource identifier within that namespace.
        """
        self.namespace = namespace
        self.identifier = identifier
        super().__init__(
            f"offline mode: no cached {namespace} response for {identifier}. "
            f"Run without --offline to populate the cache."
        )


@dataclass
class CacheStats:
    """Summary of the cache contents."""

    entries: int
    expired_entries: int
    size_bytes: int
    path: str

    def to_dict(self) -> dict[str, Any]:
        """Convert the stats to a JSON-serializable dictionary."""
        return {
            "entries": self.entries,
            "expired_entries": self.expired_entries,
            "size_bytes": self.size_bytes,
            "path": self.path,
        }


class ResponseCache:
    """A TTL-based SQLite cache for JSON-serializable responses."""

    def __init__(
        self,
        directory: Path | None = None,
        *,
        enabled: bool | None = None,
        offline: bool = False,
        ttl_overrides: dict[str, int] | None = None,
    ) -> None:
        """Initialize the cache.

        Args:
            directory: Directory that holds the database. Defaults to the
                platform cache directory.
            enabled: Whether caching is active. Defaults to the
                ``DEPCHECK_NO_CACHE`` environment variable.
            offline: When True, cache misses are reported instead of triggering
                network access by the caller.
            ttl_overrides: Per-namespace TTL overrides in seconds.
        """
        self._directory = Path(directory) if directory is not None else cache_directory()
        self._enabled = not _env_flag(CACHE_DISABLE_ENV) if enabled is None else enabled
        self._offline = offline
        self._ttl_overrides = dict(ttl_overrides or {})
        self._local = threading.local()
        self._schema_lock = threading.Lock()

    def ttl_for(self, namespace: str, default: int) -> int:
        """Return the time-to-live to use for a namespace.

        Args:
            namespace: The API or subsystem the entry belongs to.
            default: The TTL to use when no override is configured.

        Returns:
            The effective TTL in seconds.
        """
        return self._ttl_overrides.get(namespace, default)

    @property
    def enabled(self) -> bool:
        """Whether the cache is active."""
        return self._enabled

    @property
    def offline(self) -> bool:
        """Whether the cache is in offline-only mode."""
        return self._offline

    @property
    def path(self) -> Path:
        """Path of the cache database."""
        return self._directory / CACHE_DB_NAME

    def _connect(self) -> sqlite3.Connection:
        """Open (and lazily create) the cache database for the current thread.

        Each thread gets its own SQLite connection: the ``sqlite3`` module
        refuses to share a connection across threads by default, and depcheck
        writes to the cache from a worker pool.

        Returns:
            An open SQLite connection owned by the calling thread.
        """
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            return connection

        with self._schema_lock:
            self._directory.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(
                self.path,
                timeout=10.0,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS entries (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
        self._local.connection = connection
        return connection

    def close(self) -> None:
        """Close the database connection owned by the calling thread."""
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            connection.close()
            self._local.connection = None

    def make_key(self, namespace: str, identifier: str) -> str:
        """Build a stable cache key.

        Args:
            namespace: The API or subsystem the entry belongs to.
            identifier: The resource identifier within that namespace.

        Returns:
            A hex digest usable as a primary key.
        """
        raw = f"{namespace}\x00{identifier}".encode()
        return hashlib.sha256(raw).hexdigest()

    def get(self, namespace: str, identifier: str) -> dict[str, Any] | None:
        """Read a cached payload.

        Args:
            namespace: The API or subsystem the entry belongs to.
            identifier: The resource identifier within that namespace.

        Returns:
            The cached payload, or None when absent or expired.
        """
        if not self._enabled:
            return None
        try:
            connection = self._connect()
            row = connection.execute(
                "SELECT value, expires_at FROM entries WHERE key = ?",
                (self.make_key(namespace, identifier),),
            ).fetchone()
        except sqlite3.Error:
            return None
        if row is None:
            return None
        value, expires_at = row
        if expires_at <= time.time():
            self.delete(namespace, identifier)
            return None
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            self.delete(namespace, identifier)
            return None
        return payload if isinstance(payload, dict) else None

    def set(
        self,
        namespace: str,
        identifier: str,
        payload: dict[str, Any],
        ttl: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        """Store a payload in the cache.

        Args:
            namespace: The API or subsystem the entry belongs to.
            identifier: The resource identifier within that namespace.
            payload: The JSON-serializable payload to store.
            ttl: Time-to-live in seconds.
        """
        if not self._enabled or ttl <= 0:
            return
        try:
            connection = self._connect()
            now = time.time()
            connection.execute(
                "INSERT OR REPLACE INTO entries (key, value, expires_at, created_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    self.make_key(namespace, identifier),
                    json.dumps(payload),
                    now + ttl,
                    now,
                ),
            )
        except (sqlite3.Error, TypeError, ValueError):
            return

    def delete(self, namespace: str, identifier: str) -> None:
        """Remove a single entry from the cache.

        Args:
            namespace: The API or subsystem the entry belongs to.
            identifier: The resource identifier within that namespace.
        """
        try:
            connection = self._connect()
            connection.execute(
                "DELETE FROM entries WHERE key = ?",
                (self.make_key(namespace, identifier),),
            )
        except sqlite3.Error:
            return

    def clear(self) -> int:
        """Remove every entry from the cache.

        Returns:
            The number of entries that were removed.
        """
        try:
            connection = self._connect()
            cursor = connection.execute("DELETE FROM entries")
            return int(cursor.rowcount or 0)
        except sqlite3.Error:
            return 0

    def stats(self) -> CacheStats:
        """Summarize the cache contents.

        Returns:
            Statistics about the cache database.
        """
        entries = 0
        expired = 0
        try:
            connection = self._connect()
            now = time.time()
            entries = int(connection.execute("SELECT COUNT(*) FROM entries").fetchone()[0])
            expired = int(
                connection.execute(
                    "SELECT COUNT(*) FROM entries WHERE expires_at <= ?",
                    (now,),
                ).fetchone()[0]
            )
        except sqlite3.Error:
            entries = 0
            expired = 0
        size = 0
        try:
            if self.path.exists():
                size = self.path.stat().st_size
        except OSError:
            size = 0
        return CacheStats(
            entries=entries,
            expired_entries=expired,
            size_bytes=size,
            path=str(self.path),
        )


_GLOBAL_CACHE: ResponseCache | None = None


def get_cache() -> ResponseCache:
    """Return the process-wide cache instance.

    The shared instance starts **disabled** so that importing depcheck never
    writes to disk or serves stale data behind the caller's back. The CLI turns
    it on explicitly via :func:`configure_cache`.

    Returns:
        The shared cache instance.
    """
    global _GLOBAL_CACHE
    if _GLOBAL_CACHE is None:
        _GLOBAL_CACHE = ResponseCache(
            enabled=None,
            offline=_env_flag(OFFLINE_ENV),
            ttl_overrides=_ttl_overrides_from_env(),
        )
    return _GLOBAL_CACHE


def configure_cache(
    *,
    enabled: bool | None = None,
    directory: Path | None = None,
    offline: bool = False,
    ttl_overrides: dict[str, int] | None = None,
) -> ResponseCache:
    """Configure the process-wide cache instance.

    Args:
        enabled: Whether caching is active.
        directory: Directory that holds the database.
        offline: When True, callers must serve from cache only.
        ttl_overrides: Per-namespace TTL overrides in seconds.

    Returns:
        The reconfigured shared cache instance.
    """
    global _GLOBAL_CACHE
    if _GLOBAL_CACHE is not None:
        _GLOBAL_CACHE.close()
    _GLOBAL_CACHE = ResponseCache(
        directory,
        enabled=enabled,
        offline=offline,
        ttl_overrides=ttl_overrides if ttl_overrides is not None else _ttl_overrides_from_env(),
    )
    return _GLOBAL_CACHE


def reset_cache() -> None:
    """Drop the process-wide cache instance (used by tests)."""
    global _GLOBAL_CACHE
    if _GLOBAL_CACHE is not None:
        _GLOBAL_CACHE.close()
    _GLOBAL_CACHE = None
