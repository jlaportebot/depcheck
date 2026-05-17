"""OSV.dev API client for checking package vulnerabilities."""

from __future__ import annotations

from typing import Any

import httpx

from depcheck.models import Vulnerability

# OSV.dev API URLs
OSV_API_URL = "https://api.osv.dev/v1"
OSV_QUERY_URL = f"{OSV_API_URL}/query"

# Timeout for API requests (seconds)
REQUEST_TIMEOUT = 30.0


class OSVClient:
    """Client for querying the OSV.dev vulnerability database."""

    def __init__(self, timeout: float = REQUEST_TIMEOUT) -> None:
        """Initialize the OSV client.

        Args:
            timeout: Request timeout in seconds.
        """
        self._client = httpx.Client(timeout=timeout, follow_redirects=True)

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
        return [self._parse_vulnerability(v) for v in vulns]

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
                elif any(v == "H" for v in impact_values):
                    return "HIGH"
                else:
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
