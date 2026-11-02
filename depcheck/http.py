"""Shared HTTP client construction for depcheck.

Every network-backed module (PyPI, OSV, advisories, search) needs an HTTP
client. Building them ad hoc meant every module paid its own connection
setup and none of them shared a User-Agent. This module centralises client
construction so connection reuse, retry policy and identification are
consistent.
"""

from __future__ import annotations

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
