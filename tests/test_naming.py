"""Tests for depcheck.naming — package name normalization."""

from __future__ import annotations

from depcheck.naming import canonicalize, normalize_dist_name, normalize_package_name


class TestNormalizePackageName:
    """Tests for normalize_package_name (PEP 503)."""

    def test_lowercase(self) -> None:
        assert normalize_package_name("Requests") == "requests"

    def test_underscores_to_hyphens(self) -> None:
        assert normalize_package_name("my_package") == "my-package"

    def test_dots_to_hyphens(self) -> None:
        assert normalize_package_name("zope.interface") == "zope-interface"

    def test_multiple_separators(self) -> None:
        assert normalize_package_name("my__package") == "my-package"
        assert normalize_package_name("my..package") == "my-package"
        assert normalize_package_name("my_-_.package") == "my-package"

    def test_already_normalized(self) -> None:
        assert normalize_package_name("requests") == "requests"
        assert normalize_package_name("my-package") == "my-package"

    def test_mixed_case_and_separators(self) -> None:
        assert normalize_package_name("My_Package.Name") == "my-package-name"

    def test_starts_with_underscore(self) -> None:
        assert normalize_package_name("_private") == "-private"

    def test_numbers_preserved(self) -> None:
        assert normalize_package_name("package123") == "package123"
        assert normalize_package_name("pkg_123_test") == "pkg-123-test"


class TestNormalizeDistName:
    """Tests for normalize_dist_name (alias for normalize_package_name)."""

    def test_alias_works(self) -> None:
        assert normalize_dist_name("Requests") == "requests"
        assert normalize_dist_name("My_Package") == "my-package"

    def test_same_as_normalize_package_name(self) -> None:
        test_cases = ["Requests", "my_package", "zope.interface", "My_Package.Name"]
        for case in test_cases:
            assert normalize_dist_name(case) == normalize_package_name(case)


class TestCanonicalize:
    """Tests for canonicalize — strips extras and markers."""

    def test_strips_extras(self) -> None:
        assert canonicalize("requests[security]") == "requests"
        assert canonicalize("package[extra1,extra2]") == "package"

    def test_strips_markers(self) -> None:
        assert canonicalize('requests; python_version>="3.8"') == "requests"
        assert canonicalize('package>=1.0; sys_platform=="win32"') == "package"

    def test_strips_both_extras_and_markers(self) -> None:
        assert canonicalize('requests[security]>=2.28; python_version>="3.8"') == "requests"

    def test_preserves_version_specifier(self) -> None:
        # canonicalize should only strip extras/markers, not version specifiers
        # but the name returned should be normalized
        assert canonicalize("requests>=2.28") == "requests"
        assert canonicalize("my_package==1.0.0") == "my-package"

    def test_normalizes_name(self) -> None:
        assert canonicalize("My_Package[extra]") == "my-package"
        assert canonicalize("Zope.Interface>=5.0") == "zope-interface"

    def test_empty_string(self) -> None:
        assert canonicalize("") == ""

    def test_no_extras_or_markers(self) -> None:
        assert canonicalize("requests") == "requests"
