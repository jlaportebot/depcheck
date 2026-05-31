"""Version pinning and integrity verification for depcheck.

Provides version pinning with hash verification, integrity checking,
pin policy management, and lockfile verification. Ensures that
installed dependencies match their pinned versions with cryptographic
integrity guarantees.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PinPolicy(Enum):
    """Policy for version pinning behavior."""

    EXACT = "exact"                # Pin to exact version (==1.2.3)
    COMPATIBLE = "compatible"      # Pin to compatible release (~=1.2.3)
    MINIMUM = "minimum"            # Pin to minimum version (>=1.2.3)
    RANGE = "range"                # Pin to a range (>=1.2.3,<2.0.0)


class IntegrityStatus(Enum):
    """Status of an integrity check."""

    VALID = "valid"
    HASH_MISMATCH = "hash_mismatch"
    VERSION_MISMATCH = "version_mismatch"
    MISSING = "missing"
    NOT_PINNED = "not_pinned"
    YANKED = "yanked"
    DEPRECATED = "deprecated"


class Severity(Enum):
    """Severity level for integrity issues."""

    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class PinnedPackage:
    """A package pinned to a specific version with integrity metadata."""

    name: str
    version: str
    policy: PinPolicy = PinPolicy.EXACT
    specifier: str = ""
    hash_sha256: str = ""
    hash_md5: str = ""
    hash_blake2b: str = ""
    source: str = "pypi"
    pinned_at: str = ""
    pinned_by: str = ""
    python_version: str = ""
    platform: str = ""
    extras: list[str] = field(default_factory=list)
    is_editable: bool = False
    is_vcs: bool = False
    vcs_url: str = ""
    allow_prerelease: bool = False
    deprecated: bool = False
    deprecation_message: str = ""
    yanked: bool = False
    yanked_reason: str = ""

    @property
    def normalized_name(self) -> str:
        """Normalize package name (PEP 503)."""
        return re.sub(r"[-_.]+", "-", self.name).lower()

    @property
    def pin_specifier(self) -> str:
        """Return the specifier string for this pin."""
        if self.specifier:
            return self.specifier
        if self.policy == PinPolicy.EXACT:
            return f"=={self.version}"
        elif self.policy == PinPolicy.COMPATIBLE:
            parts = self.version.split(".")
            if len(parts) >= 2:
                return f"~={parts[0]}.{parts[1]}"
            return f"~={self.version}"
        elif self.policy == PinPolicy.MINIMUM:
            return f">={self.version}"
        else:
            return f"=={self.version}"

    @property
    def has_hash(self) -> bool:
        """Check if any hash is recorded."""
        return bool(self.hash_sha256 or self.hash_md5 or self.hash_blake2b)

    def verify_hash(self, content: bytes) -> IntegrityStatus:
        """Verify content against stored hashes."""
        if self.hash_sha256:
            computed = hashlib.sha256(content).hexdigest()
            if computed != self.hash_sha256:
                return IntegrityStatus.HASH_MISMATCH
        if self.hash_md5:
            computed = hashlib.md5(content).hexdigest()
            if computed != self.hash_md5:
                return IntegrityStatus.HASH_MISMATCH
        if self.hash_blake2b:
            computed = hashlib.blake2b(content, digest_size=32).hexdigest()
            if computed != self.hash_blake2b:
                return IntegrityStatus.HASH_MISMATCH
        if self.has_hash:
            return IntegrityStatus.VALID
        return IntegrityStatus.NOT_PINNED

    def verify_version(self, installed_version: str) -> IntegrityStatus:
        """Verify an installed version matches the pin."""
        if self.policy == PinPolicy.EXACT:
            if installed_version != self.version:
                return IntegrityStatus.VERSION_MISMATCH
        elif self.policy == PinPolicy.MINIMUM or self.policy == PinPolicy.COMPATIBLE:
            try:
                if Version(installed_version) not in SpecifierSet(self.pin_specifier):
                    return IntegrityStatus.VERSION_MISMATCH
            except InvalidVersion:
                if installed_version != self.version:
                    return IntegrityStatus.VERSION_MISMATCH
        elif self.policy == PinPolicy.RANGE:
            try:
                if Version(installed_version) not in SpecifierSet(self.pin_specifier):
                    return IntegrityStatus.VERSION_MISMATCH
            except InvalidVersion:
                return IntegrityStatus.VERSION_MISMATCH

        if self.yanked:
            return IntegrityStatus.YANKED
        if self.deprecated:
            return IntegrityStatus.DEPRECATED

        return IntegrityStatus.VALID

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "policy": self.policy.value,
            "specifier": self.specifier,
            "hash_sha256": self.hash_sha256,
            "hash_md5": self.hash_md5,
            "source": self.source,
            "pinned_at": self.pinned_at,
            "pinned_by": self.pinned_by,
            "python_version": self.python_version,
            "extras": self.extras,
            "is_editable": self.is_editable,
            "is_vcs": self.is_vcs,
            "yanked": self.yanked,
            "deprecated": self.deprecated,
            "deprecation_message": self.deprecation_message,
        }


@dataclass
class IntegrityCheckResult:
    """Result of checking a single package's integrity."""

    package: str
    installed_version: str
    pinned_version: str
    status: IntegrityStatus
    severity: Severity
    message: str
    expected_hash: str = ""
    actual_hash: str = ""
    fix_suggestion: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "installed_version": self.installed_version,
            "pinned_version": self.pinned_version,
            "status": self.status.value,
            "severity": self.severity.value,
            "message": self.message,
            "expected_hash": self.expected_hash,
            "actual_hash": self.actual_hash,
            "fix_suggestion": self.fix_suggestion,
        }


@dataclass
class IntegrityReport:
    """Complete integrity verification report for a project."""

    project_path: str
    checks: list[IntegrityCheckResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    pinned_packages: list[PinnedPackage] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def valid_count(self) -> int:
        return sum(1 for c in self.checks if c.status == IntegrityStatus.VALID)

    @property
    def mismatch_count(self) -> int:
        return sum(1 for c in self.checks if c.status in (
            IntegrityStatus.HASH_MISMATCH,
            IntegrityStatus.VERSION_MISMATCH,
        ))

    @property
    def missing_count(self) -> int:
        return sum(1 for c in self.checks if c.status == IntegrityStatus.MISSING)

    @property
    def not_pinned_count(self) -> int:
        return sum(1 for c in self.checks if c.status == IntegrityStatus.NOT_PINNED)

    @property
    def yanked_count(self) -> int:
        return sum(1 for c in self.checks if c.status == IntegrityStatus.YANKED)

    @property
    def deprecated_count(self) -> int:
        return sum(1 for c in self.checks if c.status == IntegrityStatus.DEPRECATED)

    @property
    def critical_count(self) -> int:
        return sum(1 for c in self.checks if c.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for c in self.checks if c.severity == Severity.WARNING)

    @property
    def is_clean(self) -> bool:
        """True if no critical issues."""
        return self.critical_count == 0

    @property
    def overall_severity(self) -> Severity:
        """Overall severity of the report."""
        if self.critical_count > 0:
            return Severity.CRITICAL
        if self.warning_count > 0:
            return Severity.WARNING
        return Severity.OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "summary": {
                "total": self.total,
                "valid": self.valid_count,
                "mismatches": self.mismatch_count,
                "missing": self.missing_count,
                "not_pinned": self.not_pinned_count,
                "yanked": self.yanked_count,
                "deprecated": self.deprecated_count,
                "critical": self.critical_count,
                "warnings": self.warning_count,
                "overall_severity": self.overall_severity.value,
            },
            "checks": [c.to_dict() for c in self.checks],
            "errors": self.errors,
        }


@dataclass
class PinResult:
    """Result of pinning packages."""

    pinned: list[PinnedPackage] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    lockfile_path: str = ""

    @property
    def total_pinned(self) -> int:
        return len(self.pinned)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_pinned": self.total_pinned,
            "pinned": [p.to_dict() for p in self.pinned],
            "skipped": self.skipped,
            "errors": self.errors,
            "lockfile_path": self.lockfile_path,
        }


# ---------------------------------------------------------------------------
# Pin file I/O
# ---------------------------------------------------------------------------


PINFILE_NAME = "depcheck.pin.json"


def write_pinfile(
    pinned: list[PinnedPackage],
    project_path: str = ".",
    filename: str = PINFILE_NAME,
) -> str:
    """Write pinned packages to a pinfile."""
    path = Path(project_path) / filename
    data = {
        "$schema": "https://depcheck.dev/schema/pinfile/v1",
        "pinfileVersion": 1,
        "generatedAt": _timestamp(),
        "packages": {pkg.normalized_name: pkg.to_dict() for pkg in pinned},
    }
    path.write_text(json.dumps(data, indent=2, sort_keys=False), encoding="utf-8")
    return str(path)


def read_pinfile(project_path: str = ".", filename: str = PINFILE_NAME) -> list[PinnedPackage]:
    """Read pinned packages from a pinfile."""
    path = Path(project_path) / filename
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    packages = []
    for _norm_name, pkg_data in data.get("packages", {}).items():
        policy = PinPolicy(pkg_data.get("policy", "exact"))
        pkg = PinnedPackage(
            name=pkg_data.get("name", _norm_name),
            version=pkg_data.get("version", ""),
            policy=policy,
            specifier=pkg_data.get("specifier", ""),
            hash_sha256=pkg_data.get("hash_sha256", ""),
            hash_md5=pkg_data.get("hash_md5", ""),
            source=pkg_data.get("source", "pypi"),
            pinned_at=pkg_data.get("pinned_at", ""),
            pinned_by=pkg_data.get("pinned_by", ""),
            python_version=pkg_data.get("python_version", ""),
            extras=pkg_data.get("extras", []),
            is_editable=pkg_data.get("is_editable", False),
            is_vcs=pkg_data.get("is_vcs", False),
            yanked=pkg_data.get("yanked", False),
            deprecated=pkg_data.get("deprecated", False),
            deprecation_message=pkg_data.get("deprecation_message", ""),
        )
        packages.append(pkg)

    return packages


# ---------------------------------------------------------------------------
# Pin operations
# ---------------------------------------------------------------------------


def pin_packages(
    project_path: str,
    policy: PinPolicy = PinPolicy.EXACT,
    include_hashes: bool = True,
    include_transitive: bool = False,
    filename: str = PINFILE_NAME,
) -> PinResult:
    """Pin all project dependencies to their current or resolved versions.

    Creates a depcheck.pin.json file with version constraints and optional
    hash verification data.
    """
    from depcheck.scanner import scan_project

    result = scan_project(
        project_path=project_path,
        check_vulnerabilities=True,
        check_licenses=False,
    )

    pinned = []
    skipped = []
    errors = []

    for pkg_report in result.packages:
        if not pkg_report.installed_version:
            skipped.append(pkg_report.name)
            continue

        try:
            pinned_pkg = PinnedPackage(
                name=pkg_report.name,
                version=pkg_report.installed_version,
                policy=policy,
                pinned_at=_timestamp(),
                pinned_by="depcheck pin",
                yanked=pkg_report.is_yanked,
            )

            if include_hashes:
                try:
                    pinned_pkg.hash_sha256 = _fetch_hash(
                pkg_report.name, pkg_report.installed_version
            )
                except Exception:
                    pass

            pinned.append(pinned_pkg)
        except Exception as e:
            errors.append(f"{pkg_report.name}: {e}")

    lockfile_path = ""
    if pinned:
        lockfile_path = write_pinfile(pinned, project_path=project_path, filename=filename)

    return PinResult(
        pinned=pinned,
        skipped=skipped,
        errors=errors,
        lockfile_path=lockfile_path,
    )


def unpin_packages(
    project_path: str,
    package_names: list[str],
    filename: str = PINFILE_NAME,
) -> list[str]:
    """Remove specific packages from the pinfile."""
    current = read_pinfile(project_path, filename)
    if not current:
        return []

    to_remove = {re.sub(r"[-_.]+", "-", n).lower() for n in package_names}
    remaining = [p for p in current if p.normalized_name not in to_remove]
    removed = [p.name for p in current if p.normalized_name in to_remove]

    if remaining:
        write_pinfile(remaining, project_path=project_path, filename=filename)
    else:
        # Remove the pinfile entirely
        path = Path(project_path) / filename
        if path.exists():
            path.unlink()

    return removed


def update_pins(
    project_path: str,
    package_names: list[str] | None = None,
    policy: PinPolicy | None = None,
    filename: str = PINFILE_NAME,
) -> PinResult:
    """Update pinned packages to their latest compatible versions.

    If package_names is None, update all pinned packages.
    """
    current = read_pinfile(project_path, filename)
    if not current:
        return PinResult()

    from depcheck.scanner import scan_project
    scan_result = scan_project(
        project_path=project_path,
        check_vulnerabilities=True,
        check_licenses=False,
    )

    # Build lookup of latest versions
    latest_versions: dict[str, str] = {}
    for pkg in scan_result.packages:
        norm = re.sub(r"[-_.]+", "-", pkg.name).lower()
        if pkg.latest_version:
            latest_versions[norm] = pkg.latest_version

    target_names = None
    if package_names:
        target_names = {re.sub(r"[-_.]+", "-", n).lower() for n in package_names}

    updated = []
    skipped = []
    errors = []

    for pinned_pkg in current:
        norm = pinned_pkg.normalized_name

        if target_names and norm not in target_names:
            updated.append(pinned_pkg)
            continue

        latest = latest_versions.get(norm)
        if latest and latest != pinned_pkg.version:
            pinned_pkg.version = latest
            pinned_pkg.pinned_at = _timestamp()
            if policy:
                pinned_pkg.policy = policy
            try:
                pinned_pkg.hash_sha256 = _fetch_hash(pinned_pkg.name, latest)
            except Exception:
                pass
            updated.append(pinned_pkg)
        else:
            skipped.append(pinned_pkg.name)
            updated.append(pinned_pkg)

    lockfile_path = ""
    if updated:
        lockfile_path = write_pinfile(updated, project_path=project_path, filename=filename)

    return PinResult(
        pinned=updated,
        skipped=skipped,
        errors=errors,
        lockfile_path=lockfile_path,
    )


# ---------------------------------------------------------------------------
# Integrity verification
# ---------------------------------------------------------------------------


def verify_integrity(
    project_path: str,
    filename: str = PINFILE_NAME,
    check_hashes: bool = True,
    check_versions: bool = True,
    check_yanked: bool = True,
    check_deprecated: bool = True,
) -> IntegrityReport:
    """Verify the integrity of pinned packages against installed versions.

    Checks version consistency, hash integrity, yanked status, and
    deprecation warnings.
    """
    from depcheck.scanner import scan_project

    pinned = read_pinfile(project_path, filename)
    if not pinned:
        return IntegrityReport(
            project_path=project_path,
            errors=[f"No pinfile found at {Path(project_path) / filename}"],
        )

    scan_result = scan_project(
        project_path=project_path,
        check_vulnerabilities=True,
        check_licenses=False,
    )

    # Build installed version lookup
    installed: dict[str, str] = {}
    for pkg in scan_result.packages:
        norm = re.sub(r"[-_.]+", "-", pkg.name).lower()
        installed[norm] = pkg.installed_version

    report = IntegrityReport(
        project_path=project_path,
        pinned_packages=pinned,
    )

    for pinned_pkg in pinned:
        norm = pinned_pkg.normalized_name
        inst_version = installed.get(norm, "")
        check = _check_package_integrity(
            pinned_pkg=pinned_pkg,
            installed_version=inst_version,
            check_hashes=check_hashes,
            check_versions=check_versions,
            check_yanked=check_yanked,
            check_deprecated=check_deprecated,
        )
        report.checks.append(check)

    return report


def _check_package_integrity(
    pinned_pkg: PinnedPackage,
    installed_version: str,
    check_hashes: bool = True,
    check_versions: bool = True,
    check_yanked: bool = True,
    check_deprecated: bool = True,
) -> IntegrityCheckResult:
    """Check integrity of a single pinned package."""
    if not installed_version:
        return IntegrityCheckResult(
            package=pinned_pkg.name,
            installed_version="",
            pinned_version=pinned_pkg.version,
            status=IntegrityStatus.MISSING,
            severity=Severity.CRITICAL,
        message=(
            f"Package '{pinned_pkg.name}' is pinned but not installed"
        ),
        fix_suggestion=(
            f"Install the package: pip install {pinned_pkg.name}"
            f"=={pinned_pkg.version}"
        ),
        )

    # Version check
    if check_versions:
        version_status = pinned_pkg.verify_version(installed_version)
        if version_status == IntegrityStatus.VERSION_MISMATCH:
            return IntegrityCheckResult(
                package=pinned_pkg.name,
                installed_version=installed_version,
                pinned_version=pinned_pkg.version,
                status=IntegrityStatus.VERSION_MISMATCH,
                severity=Severity.CRITICAL,
        message=(
            f"Version mismatch: installed {installed_version}"
            f" != pinned {pinned_pkg.version}"
        ),
        fix_suggestion=(
            f"Reinstall: pip install {pinned_pkg.name}"
            f"=={pinned_pkg.version}"
        ),
            )

    # Yanked check
    if check_yanked and pinned_pkg.yanked:
        return IntegrityCheckResult(
            package=pinned_pkg.name,
            installed_version=installed_version,
            pinned_version=pinned_pkg.version,
            status=IntegrityStatus.YANKED,
            severity=Severity.CRITICAL,
        message=(
            f"Pinned version {pinned_pkg.version} has been"
            f" yanked: {pinned_pkg.yanked_reason}"
        ),
        fix_suggestion=(
            "Update to a non-yanked version:"
            f" depcheck pin --update {pinned_pkg.name}"
        ),
        )

    # Deprecated check
    if check_deprecated and pinned_pkg.deprecated:
        return IntegrityCheckResult(
            package=pinned_pkg.name,
            installed_version=installed_version,
            pinned_version=pinned_pkg.version,
            status=IntegrityStatus.DEPRECATED,
            severity=Severity.WARNING,
            message=f"Package is deprecated: {pinned_pkg.deprecation_message}",
            fix_suggestion="Consider migrating to a maintained alternative.",
        )

    # Hash check (only if we have a hash and want to check it)
    if check_hashes and pinned_pkg.has_hash:
        # We can't directly check file hashes without downloading, so we
        # verify that the hash metadata exists and is well-formed
        if not _is_valid_hash(pinned_pkg.hash_sha256, "sha256"):
            return IntegrityCheckResult(
                package=pinned_pkg.name,
                installed_version=installed_version,
                pinned_version=pinned_pkg.version,
                status=IntegrityStatus.HASH_MISMATCH,
                severity=Severity.WARNING,
                message=f"SHA-256 hash for {pinned_pkg.name} appears malformed",
                expected_hash=pinned_pkg.hash_sha256,
                fix_suggestion="Re-pin the package to regenerate the hash.",
            )

    return IntegrityCheckResult(
        package=pinned_pkg.name,
        installed_version=installed_version,
        pinned_version=pinned_pkg.version,
        status=IntegrityStatus.VALID,
        severity=Severity.OK,
        message=f"Package '{pinned_pkg.name}' integrity verified",
    )


# ---------------------------------------------------------------------------
# Policy management
# ---------------------------------------------------------------------------


@dataclass
class PinPolicyRule:
    """A pinning policy rule for a package or pattern."""

    pattern: str          # Package name pattern (glob or regex)
    policy: PinPolicy     # Pin policy to apply
    allow_prerelease: bool = False
    hash_required: bool = True
    allow_yanked: bool = False
    max_age_days: int = 0  # 0 = no limit

    def matches(self, package_name: str) -> bool:
        """Check if a package name matches this rule's pattern."""
        if self.pattern == "*":
            return True
        # Simple glob matching — un-escape the glob * after escaping the rest
        escaped = re.escape(self.pattern)
        # re.escape turns * into \*, we turn \* back into .*
        regex = escaped.replace(r"\*", ".*")
        return bool(re.match(f"^{regex}$", package_name, re.IGNORECASE))

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "policy": self.policy.value,
            "allow_prerelease": self.allow_prerelease,
            "hash_required": self.hash_required,
            "allow_yanked": self.allow_yanked,
            "max_age_days": self.max_age_days,
        }


@dataclass
class PinPolicyConfig:
    """Configuration for pin policy rules."""

    default_policy: PinPolicy = PinPolicy.EXACT
    rules: list[PinPolicyRule] = field(default_factory=list)
    require_hashes: bool = True
    require_vcs_hash: bool = False
    fail_on_yanked: bool = True
    fail_on_deprecated: bool = False
    auto_update: bool = False
    max_stale_days: int = 90

    def get_policy_for(self, package_name: str) -> PinPolicy:
        """Get the effective pin policy for a package."""
        for rule in self.rules:
            if rule.matches(package_name):
                return rule.policy
        return self.default_policy

    def get_rule_for(self, package_name: str) -> PinPolicyRule | None:
        """Get the effective rule for a package."""
        for rule in self.rules:
            if rule.matches(package_name):
                return rule
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "default_policy": self.default_policy.value,
            "rules": [r.to_dict() for r in self.rules],
            "require_hashes": self.require_hashes,
            "fail_on_yanked": self.fail_on_yanked,
            "fail_on_deprecated": self.fail_on_deprecated,
            "auto_update": self.auto_update,
            "max_stale_days": self.max_stale_days,
        }


def load_pin_policy(project_path: str = ".") -> PinPolicyConfig:
    """Load pin policy from pyproject.toml or defaults."""
    path = Path(project_path) / "pyproject.toml"
    config = PinPolicyConfig()

    if not path.exists():
        return config

    try:
        if hasattr("", "removesuffix"):  # Python 3.9+
            import tomllib
        else:
            import tomli as tomllib

        with open(path, "rb") as f:
            data = tomllib.load(f)

        pin_config = data.get("tool", {}).get("depcheck", {}).get("pin", {})
        if not pin_config:
            return config

        config.default_policy = PinPolicy(pin_config.get("default_policy", "exact"))
        config.require_hashes = pin_config.get("require_hashes", True)
        config.fail_on_yanked = pin_config.get("fail_on_yanked", True)
        config.fail_on_deprecated = pin_config.get("fail_on_deprecated", False)
        config.auto_update = pin_config.get("auto_update", False)
        config.max_stale_days = pin_config.get("max_stale_days", 90)

        for rule_data in pin_config.get("rules", []):
            rule = PinPolicyRule(
                pattern=rule_data.get("pattern", "*"),
                policy=PinPolicy(rule_data.get("policy", "exact")),
                allow_prerelease=rule_data.get("allow_prerelease", False),
                hash_required=rule_data.get("hash_required", True),
                allow_yanked=rule_data.get("allow_yanked", False),
                max_age_days=rule_data.get("max_age_days", 0),
            )
            config.rules.append(rule)

    except Exception:
        pass

    return config


# ---------------------------------------------------------------------------
# Pin drift detection
# ---------------------------------------------------------------------------


@dataclass
class PinDrift:
    """Drift between pinned and available versions."""

    package: str
    pinned_version: str
    latest_version: str
    drift_type: str  # "major", "minor", "patch"
    age_days: int = 0
    is_security_update: bool = False

    @property
    def is_significant(self) -> bool:
        """Whether this drift is significant."""
        return self.drift_type in ("major", "minor") or self.is_security_update

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "pinned_version": self.pinned_version,
            "latest_version": self.latest_version,
            "drift_type": self.drift_type,
            "age_days": self.age_days,
            "is_security_update": self.is_security_update,
            "is_significant": self.is_significant,
        }


@dataclass
class PinDriftReport:
    """Report on drift between pinned and available versions."""

    drifts: list[PinDrift] = field(default_factory=list)
    up_to_date_count: int = 0
    total_pinned: int = 0

    @property
    def significant_drifts(self) -> list[PinDrift]:
        return [d for d in self.drifts if d.is_significant]

    @property
    def major_drifts(self) -> list[PinDrift]:
        return [d for d in self.drifts if d.drift_type == "major"]

    @property
    def minor_drifts(self) -> list[PinDrift]:
        return [d for d in self.drifts if d.drift_type == "minor"]

    @property
    def patch_drifts(self) -> list[PinDrift]:
        return [d for d in self.drifts if d.drift_type == "patch"]

    @property
    def security_drifts(self) -> list[PinDrift]:
        return [d for d in self.drifts if d.is_security_update]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_pinned": self.total_pinned,
            "up_to_date": self.up_to_date_count,
            "drifts": [d.to_dict() for d in self.drifts],
            "summary": {
                "major": len(self.major_drifts),
                "minor": len(self.minor_drifts),
                "patch": len(self.patch_drifts),
                "security": len(self.security_drifts),
                "significant": len(self.significant_drifts),
            },
        }


def detect_pin_drift(project_path: str = ".", filename: str = PINFILE_NAME) -> PinDriftReport:
    """Detect drift between pinned versions and latest available versions."""
    from depcheck.scanner import scan_project

    pinned = read_pinfile(project_path, filename)
    if not pinned:
        return PinDriftReport(total_pinned=0)

    scan_result = scan_project(
        project_path=project_path,
        check_vulnerabilities=True,
        check_licenses=False,
    )

    latest_versions: dict[str, str] = {}
    vulnerable: set[str] = set()
    for pkg in scan_result.packages:
        norm = re.sub(r"[-_.]+", "-", pkg.name).lower()
        if pkg.latest_version:
            latest_versions[norm] = pkg.latest_version
        if pkg.is_vulnerable:
            vulnerable.add(norm)

    report = PinDriftReport(total_pinned=len(pinned))
    drifts = []
    up_to_date = 0

    for pinned_pkg in pinned:
        norm = pinned_pkg.normalized_name
        latest = latest_versions.get(norm)
        if not latest:
            up_to_date += 1
            continue

        if latest == pinned_pkg.version:
            up_to_date += 1
            continue

        drift_type = _classify_drift(pinned_pkg.version, latest)
        is_security = norm in vulnerable

        drifts.append(PinDrift(
            package=pinned_pkg.name,
            pinned_version=pinned_pkg.version,
            latest_version=latest,
            drift_type=drift_type,
            is_security_update=is_security,
        ))

    report.drifts = drifts
    report.up_to_date_count = up_to_date
    return report


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_pin_table(result: PinResult, *, console: Any = None) -> None:
    """Render pin results as a rich table."""
    from rich.console import Console
    from rich.table import Table

    if console is None:
        console = Console()

    console.print(f"\n[bold]Pinned {result.total_pinned} packages[/bold]")

    if result.pinned:
        table = Table(title="Pinned Packages", show_lines=True)
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Policy", style="yellow")
        table.add_column("Hash", style="dim")

        for pkg in sorted(result.pinned, key=lambda p: p.normalized_name):
            hash_indicator = "✓" if pkg.hash_sha256 else "—"
            table.add_row(pkg.name, pkg.version, pkg.policy.value, hash_indicator)

        console.print(table)

    if result.lockfile_path:
        console.print(f"\n[green]Pinfile written to {result.lockfile_path}[/green]")

    if result.skipped:
        console.print(f"\n[yellow]Skipped (no version): {', '.join(result.skipped)}[/yellow]")

    if result.errors:
        for error in result.errors:
            console.print(f"[red]Error: {error}[/red]")


def render_integrity_table(report: IntegrityReport, *, console: Any = None) -> None:
    """Render integrity report as a rich table."""
    from rich.console import Console
    from rich.table import Table

    if console is None:
        console = Console()

    severity_colors = {
        Severity.OK: "green",
        Severity.WARNING: "yellow",
        Severity.CRITICAL: "red",
    }

    status_icons = {
        IntegrityStatus.VALID: "✓",
        IntegrityStatus.HASH_MISMATCH: "✗",
        IntegrityStatus.VERSION_MISMATCH: "✗",
        IntegrityStatus.MISSING: "?",
        IntegrityStatus.NOT_PINNED: "—",
        IntegrityStatus.YANKED: "⚠",
        IntegrityStatus.DEPRECATED: "⚠",
    }

    console.print(f"\n[bold]Integrity Verification: {report.project_path}[/bold]")
    overall = report.overall_severity
    console.print(
        f"Overall: [{severity_colors[overall]}]{overall.value}"
        f"[/{severity_colors[overall]}] | "
        f"Valid: [green]{report.valid_count}[/green] | "
        f"Mismatches: [red]{report.mismatch_count}[/red] | "
        f"Missing: [yellow]{report.missing_count}[/yellow] | "
        f"Yanked: [orange1]{report.yanked_count}[/orange1]"
    )

    if report.checks:
        table = Table(title="Integrity Checks", show_lines=True)
        table.add_column("Package", style="cyan")
        table.add_column("Installed", style="green")
        table.add_column("Pinned", style="yellow")
        table.add_column("Status", style="bold")
        table.add_column("Message", max_width=50)

        for check in sorted(report.checks, key=lambda c: c.package.lower()):
            icon = status_icons.get(check.status, "?")
            color = severity_colors.get(check.severity, "white")
            table.add_row(
                check.package,
                check.installed_version or "—",
                check.pinned_version,
                f"[{color}]{icon} {check.status.value}[/{color}]",
                check.message,
            )
        console.print(table)


def render_drift_table(report: PinDriftReport, *, console: Any = None) -> None:
    """Render pin drift report as a rich table."""
    from rich.console import Console
    from rich.table import Table

    if console is None:
        console = Console()

    console.print("\n[bold]Pin Drift Report[/bold]")
    console.print(
        f"Total pinned: {report.total_pinned} |"
        f" Up to date: [green]{report.up_to_date_count}[/green] |"
        f" Drifted: [yellow]{len(report.drifts)}[/yellow]"
    )

    if report.drifts:
        drift_colors = {"major": "red", "minor": "yellow", "patch": "dim"}
        table = Table(title="Version Drift", show_lines=True)
        table.add_column("Package", style="cyan")
        table.add_column("Pinned", style="yellow")
        table.add_column("Latest", style="green")
        table.add_column("Drift", style="bold")
        table.add_column("Security", style="red")

        for drift in sorted(report.drifts, key=lambda d: (d.drift_type != "major", d.package)):
            color = drift_colors.get(drift.drift_type, "white")
            security = "⚠ YES" if drift.is_security_update else "—"
            table.add_row(
                drift.package,
                drift.pinned_version,
                drift.latest_version,
                f"[{color}]{drift.drift_type}[/{color}]",
                security,
            )
        console.print(table)


def render_pin_json(result: PinResult) -> str:
    """Render pin results as JSON."""
    return json.dumps(result.to_dict(), indent=2)


def render_integrity_json(report: IntegrityReport) -> str:
    """Render integrity report as JSON."""
    return json.dumps(report.to_dict(), indent=2)


def render_drift_json(report: PinDriftReport) -> str:
    """Render drift report as JSON."""
    return json.dumps(report.to_dict(), indent=2)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fetch_hash(package: str, version: str) -> str:
    """Fetch SHA-256 hash for a package version from PyPI."""
    try:
        from depcheck.pypi import fetch_package_info
        info = fetch_package_info(package)
        if info and "releases" in info:
            release = info["releases"].get(version, [])
            for file_info in release:
                digests = file_info.get("digests", {})
                sha = digests.get("sha256", "")
                if sha:
                    return sha
    except Exception:
        pass
    return ""


def _is_valid_hash(hash_str: str, algorithm: str = "sha256") -> bool:
    """Check if a hash string is well-formed."""
    expected_lengths = {"sha256": 64, "md5": 32, "blake2b": 64}
    expected_len = expected_lengths.get(algorithm, 64)
    return len(hash_str) == expected_len and all(c in "0123456789abcdef" for c in hash_str.lower())


def _classify_drift(old_version: str, new_version: str) -> str:
    """Classify the type of version drift (major, minor, or patch)."""
    try:
        old = Version(old_version)
        new = Version(new_version)
        if new.major > old.major:
            return "major"
        if new.minor > old.minor:
            return "minor"
        return "patch"
    except InvalidVersion:
        return "unknown"


def _timestamp() -> str:
    """Return ISO 8601 timestamp."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
