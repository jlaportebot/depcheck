"""OSV.dev API client for checking package vulnerabilities."""

from __future__ import annotations

from typing import Any

import httpx

from depcheck.cache import OSV_TTL_SECONDS, OfflineCacheMissError, ResponseCache, get_cache
from depcheck.http import USER_AGENT
from depcheck.models import Vulnerability

# OSV.dev API URLs
OSV_API_URL = "https://api.osv.dev/v1"
OSV_QUERY_URL = f"{OSV_API_URL}/query"
OSV_QUERY_BATCH_URL = f"{OSV_API_URL}/querybatch"

# Timeout for API requests (seconds)
REQUEST_TIMEOUT = 30.0

# Cache namespace for OSV responses
CACHE_NAMESPACE = "osv"

# Maximum number of queries per batch request
MAX_BATCH_QUERIES = 1000


def _chunks(items: list[Any], size: int) -> list[list[Any]]:
    """Split a list into fixed-size chunks.

    Args:
        items: The list to split.
        size: Maximum chunk size.

    Returns:
        A list of chunks.
    """
    if size <= 0:
        return [list(items)]
    return [items[index : index + size] for index in range(0, len(items), size)]


class OSVClient:
    """Client for querying the OSV.dev vulnerability database."""

    def __init__(
        self,
        timeout: float = REQUEST_TIMEOUT,
        *,
        cache: ResponseCache | None = None,
        use_cache: bool = True,
    ) -> None:
        """Initialize the OSV client.

        Args:
            timeout: Request timeout in seconds.
            cache: Cache to read from and write to. Defaults to the shared
                process-wide cache.
            use_cache: Whether cached responses may be used.
        """
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        self._cache = cache if cache is not None else get_cache()
        self._use_cache = use_cache

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> OSVClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def query_vulnerabilities(self, package_name: str, version: str) -> list[Vulnerability]:
        """Query OSV.dev for vulnerabilities affecting a specific package version.

        Args:
            package_name: The PyPI package name.
            version: The version string to check.

        Returns:
            List of Vulnerability objects affecting this package version.
        """
        cache_key = f"{package_name}@{version}"
        if self._use_cache:
            cached = self._cache.get(CACHE_NAMESPACE, cache_key)
            if cached is not None:
                return [self._parse_vulnerability(v) for v in cached.get("vulns", [])]

        if self._cache.offline:
            raise OfflineCacheMissError(CACHE_NAMESPACE, cache_key)

        payload = {
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": "PyPI",
            },
        }

        try:
            response = self._client.post(OSV_QUERY_URL, json=payload)
            if response.status_code == 404:
                return []
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError:
            return []

        vulns = data.get("vulns", [])
        if self._use_cache:
            self._cache.set(
                CACHE_NAMESPACE,
                cache_key,
                {"vulns": vulns},
                ttl=self._cache.ttl_for(CACHE_NAMESPACE, OSV_TTL_SECONDS),
            )
        return [self._parse_vulnerability(v) for v in vulns]

    def query_vulnerabilities_batch(
        self,
        packages: list[tuple[str, str]],
    ) -> dict[tuple[str, str], list[Vulnerability]]:
        """Query OSV.dev for many packages in as few requests as possible.

        Cached entries are served locally; only cache misses reach the network.
        Remaining misses are sent through the batch endpoint, which accepts up
        to 1000 queries per request.

        Args:
            packages: Pairs of (package_name, version).

        Returns:
            Mapping of (package_name, version) to its vulnerabilities.
        """
        results: dict[tuple[str, str], list[Vulnerability]] = {}
        pending: list[tuple[str, str]] = []

        for key in packages:
            cache_key = f"{key[0]}@{key[1]}"
            cached = self._cache.get(CACHE_NAMESPACE, cache_key) if self._use_cache else None
            if cached is not None:
                results[key] = [self._parse_vulnerability(v) for v in cached.get("vulns", [])]
            else:
                pending.append(key)

        if pending and self._cache.offline:
            raise OfflineCacheMissError(CACHE_NAMESPACE, f"{pending[0][0]}@{pending[0][1]}")

        for batch in _chunks(pending, MAX_BATCH_QUERIES):
            results.update(self._query_batch(batch))

        return results

    def _query_batch(
        self,
        packages: list[tuple[str, str]],
    ) -> dict[tuple[str, str], list[Vulnerability]]:
        """Send one batch request to the OSV batch endpoint.

        Args:
            packages: Pairs of (package_name, version) to query.

        Returns:
            Mapping of (package_name, version) to its vulnerabilities.
        """
        if not packages:
            return {}

        queries = [
            {"version": version, "package": {"name": name, "ecosystem": "PyPI"}}
            for name, version in packages
        ]

        try:
            response = self._client.post(OSV_QUERY_BATCH_URL, json={"queries": queries})
            if response.status_code == 404:
                return {key: [] for key in packages}
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError:
            return {key: [] for key in packages}

        raw_results = data.get("results", [])
        parsed: dict[tuple[str, str], list[Vulnerability]] = {}
        for key, raw in zip(packages, raw_results, strict=False):
            vulns = raw.get("vulns", []) if isinstance(raw, dict) else []
            parsed[key] = [self._parse_vulnerability(v) for v in vulns]
            if self._use_cache:
                self._cache.set(
                    CACHE_NAMESPACE,
                    f"{key[0]}@{key[1]}",
                    {"vulns": vulns},
                    ttl=self._cache.ttl_for(CACHE_NAMESPACE, OSV_TTL_SECONDS),
                )
        return parsed

    def _parse_vulnerability(self, vuln_data: dict[str, Any]) -> Vulnerability:
        """Parse an OSV vulnerability entry into a Vulnerability object.

        Args:
            vuln_data: Raw vulnerability data from OSV API.

        Returns:
            Parsed Vulnerability object.
        """
        vuln_id = vuln_data.get("id", "UNKNOWN")
        summary = vuln_data.get("summary", "No summary available")

        # Extract severity from database_specific or severity field
        severity = self._extract_severity(vuln_data)

        # Build URL from the OSV ID
        url = f"https://osv.dev/vulnerability/{vuln_id}"

        # Collect aliases (CVE IDs, etc.)
        aliases = vuln_data.get("aliases", [])

        return Vulnerability(
            vuln_id=vuln_id,
            summary=summary,
            severity=severity,
            url=url,
            aliases=aliases,
        )

    def _extract_severity(self, vuln_data: dict[str, Any]) -> str:
        """Extract severity level from OSV vulnerability data.

        OSV provides severity in different formats depending on the source.
        We try multiple fields to find a severity rating.

        Args:
            vuln_data: Raw vulnerability data from OSV API.

        Returns:
            Severity string (e.g., "HIGH", "MEDIUM", "LOW", or "UNKNOWN").
        """
        # Try the severity field (CVSS vectors)
        severity_list = vuln_data.get("severity", [])
        for sev in severity_list:
            score_str = sev.get("score", "")
            # Parse CVSS vector string to extract base score
            if "CVSS" in score_str:
                # Example: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                parts = score_str.split("/")

                # Heuristic based on CIA impact metrics (C, I, A)
                impact_values = []
                for part in parts:
                    if any(part.startswith(x) for x in ("C:", "I:", "A:")):
                        impact_values.append(part.split(":")[1])

                if all(v == "N" for v in impact_values):
                    return "LOW"
                if any(v == "H" for v in impact_values):
                    return "HIGH"
                return "MEDIUM"

        # Try database_specific for GitHub Advisory severity
        db_specific = vuln_data.get("database_specific", {})
        if "severity" in db_specific:
            return db_specific["severity"].upper()

        # Try references for advisory info
        for ref in vuln_data.get("references", []):
            if "severity" in str(ref):
                return "MEDIUM"

        return "UNKNOWN"
