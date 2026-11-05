"""Shared HTTP client construction for depcheck.

Every network-backed module (PyPI, OSV, advisories, search) needs an HTTP
client. Building them ad hoc meant every module paid its own connection
setup and none of them shared a User-Agent. This module centralises client
construction so connection reuse, retry policy and identification are
consistent.
"""

from __future__ import annotations

from typing import Any

import httpx

from depcheck import __version__

#: Default timeout for API requests (seconds).
DEFAULT_TIMEOUT = 30.0

#: Number of retries for transient failures.
DEFAULT_RETRIES = 2

#: Backoff factor between retries (seconds).
DEFAULT_BACKOFF = 0.25

#: Connection pool size.
DEFAULT_LIMITS = httpx.Limits(max_connections=32, max_keepalive_connections=16)

#: User-Agent sent with every request.
USER_AGENT = f"depcheck/{__version__} (+https://github.com/jlaportebot/depcheck)"

#: Header used to send a previously seen ETag back to the server.
ETAG_REQUEST_HEADER = "If-None-Match"
#: Header servers echo back with the current representation's ETag.
ETAG_RESPONSE_HEADER = "etag"


class ETagStore:
    """In-memory store of ETags keyed by URL.

    Used to issue conditional (``If-None-Match``) requests so that repeated
    scans of unchanged packages avoid re-downloading and re-parsing payloads.
    """

    def __init__(self) -> None:
        self._etags: dict[str, str] = {}

    def get(self, url: str) -> str | None:
        """Return the stored ETag for ``url``, or ``None`` if unseen."""
        return self._etags.get(url)

    def set(self, url: str, etag: str) -> None:
        """Store ``etag`` for ``url``."""
        self._etags[url] = etag


def conditional_get_json(
    client: httpx.Client,
    url: str,
    etag_store: ETagStore,
) -> tuple[Any | None, str | None, int]:
    """GET a JSON endpoint conditionally using its ETag.

    Args:
        client: The HTTP client to use.
        url: The URL to fetch.
        etag_store: Store of previously seen ETags, keyed by URL.

    Returns:
        A ``(payload, etag, status_code)`` tuple:
        * ``payload`` is the parsed JSON body, or ``None`` on a 304 (not
          modified -- use the cached copy) or a 404 (not found).
        * ``etag`` is the ETag returned by the server, or the previously
          stored one on a 304.
        * ``status_code`` is the HTTP status code returned.

    Network or server errors (5xx, timeouts, ...) raise
    :class:`httpx.HTTPError`.
    """
    headers: dict[str, str] = {}
    stored_etag = etag_store.get(url)
    if stored_etag:
        headers[ETAG_REQUEST_HEADER] = stored_etag

    response = client.get(url, headers=headers)

    if response.status_code == 304:
        # Not modified -- the caller should keep using its cached copy.
        return None, stored_etag, 304

    etag = response.headers.get(ETAG_RESPONSE_HEADER) or stored_etag

    if response.status_code == 404:
        return None, None, 404

    response.raise_for_status()

    if etag:
        etag_store.set(url, etag)
    return response.json(), etag, response.status_code


def build_client(
    timeout: float = DEFAULT_TIMEOUT,
    *,
    retries: int = DEFAULT_RETRIES,
    headers: dict[str, str] | None = None,
) -> httpx.Client:
    """Build an HTTP client with depcheck's shared defaults.

    Args:
        timeout: Request timeout in seconds.
        retries: Number of retries for transient network failures.
        headers: Extra headers merged over the default User-Agent.

    Returns:
        A configured :class:`httpx.Client`.
    """
    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)
    return httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        headers=request_headers,
        limits=DEFAULT_LIMITS,
        transport=httpx.HTTPTransport(retries=retries),
    )
