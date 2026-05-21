"""PyPI API client for fetching package metadata."""

from __future__ import annotations

import datetime
from typing import Any

import httpx
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from depcheck.models import ParsedDependency

# PyPI JSON API base URL
PYPI_API_URL = "https://pypi.org/pypi"

# Timeout for API requests (seconds)
REQUEST_TIMEOUT = 30.0


class PyPIClient:
    """Client for querying the PyPI JSON API."""

    def __init__(self, timeout: float = REQUEST_TIMEOUT) -> None:
        """Initialize the PyPI client.

        Args:
            timeout: Request timeout in seconds.
        """
        self._client = httpx.Client(timeout=timeout, follow_redirects=True)

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> PyPIClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def get_package_info(self, package_name: str) -> dict[str, Any] | None:
        """Fetch package metadata from PyPI.

        Args:
            package_name: The normalized package name.

        Returns:
            Dictionary of package metadata, or None if the package was not found.
        """
        url = f"{PYPI_API_URL}/{package_name}/json"
        try:
            response = self._client.get(url)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError:
            return None

    def get_latest_version(self, package_name: str) -> str | None:
        """Get the latest stable version of a package.

        Args:
            package_name: The normalized package name.

        Returns:
            The latest version string, or None if not found.
        """
        info = self.get_package_info(package_name)
        if info is None:
            return None
        return info.get("info", {}).get("version")

    def is_version_yanked(
        self,
        package_name: str,
        version: str,
        info: dict[str, Any] | None = None,
    ) -> bool:
        """Check if a specific version of a package has been yanked.

        Args:
            package_name: The normalized package name.
            version: The version string to check.
            info: Pre-fetched package info (optional, fetched if not provided).

        Returns:
            True if the version has been yanked, False otherwise.
        """
        if info is None:
            info = self.get_package_info(package_name)
        if info is None:
            return False

        releases = info.get("releases", {})
        version_files = releases.get(version, [])
        if not version_files:
            return False

        # A version is yanked if all its files are yanked
        return all(f.get("yanked", False) for f in version_files)

    def get_last_release_date(
        self,
        package_name: str,
        info: dict[str, Any] | None = None,
    ) -> datetime.datetime | None:
        """Get the date of the most recent release for a package.

        Args:
            package_name: The normalized package name.
            info: Pre-fetched package info (optional, fetched if not provided).

        Returns:
            The datetime of the last release, or None if not found.
        """
        if info is None:
            info = self.get_package_info(package_name)
        if info is None:
            return None

        releases = info.get("releases", {})
        if not releases:
            return None

        latest_dates: list[datetime.datetime] = []
        for version, files in releases.items():
            for file_info in files:
                upload_time = file_info.get("upload_time_iso_8601")
                if upload_time:
                    try:
                        dt = datetime.datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                        latest_dates.append(dt)
                    except (ValueError, TypeError):
                        continue

        if not latest_dates:
            return None

        return max(latest_dates)

    def get_all_releases(self, package_name: str) -> dict[str, list[dict[str, Any]]]:
        """Get all releases for a package.

        Args:
            package_name: The normalized package name.

        Returns:
            Dictionary mapping version strings to file info lists.
        """
        info = self.get_package_info(package_name)
        if info is None:
            return {}
        return info.get("releases", {})

    def resolve_version(
        self, dep: ParsedDependency, info: dict[str, Any] | None = None
    ) -> str | None:
        """Resolve the installed/pinned version for a dependency.

        If the dependency has an exact version (==), return that.
        If it has a version specifier (e.g., >=1.0,<2.0), return the latest
        compatible version using packaging.specifiers.SpecifierSet.
        Otherwise, return the latest version.

        Args:
            dep: The parsed dependency.
            info: Pre-fetched package info (optional, fetched if not provided).

        Returns:
            The resolved version string, or None if not resolvable.
        """
        if dep.version:
            return dep.version

        # If no version specified, use the latest
        if info is None:
            info = self.get_package_info(dep.name)
        if info is None:
            return None

        # If there's a specifier, find the latest compatible version
        if dep.specifier:
            try:
                spec = SpecifierSet(dep.specifier)
            except Exception:
                # Invalid specifier, fall back to latest
                return info.get("info", {}).get("version")

            releases = info.get("releases", {})
            compatible_versions: list[Version] = []
            for ver_str in releases:
                try:
                    ver = Version(ver_str)
                    if ver in spec and not ver.is_prerelease and not ver.is_devrelease:
                        compatible_versions.append(ver)
                except Exception:
                    continue

            if compatible_versions:
                return str(max(compatible_versions))

        return info.get("info", {}).get("version")
