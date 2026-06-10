"""Tests for depcheck OSV.dev client module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from depcheck.osv import OSVClient


class TestOSVClientInit:
    """Tests for OSVClient initialization and context manager."""

    def test_init_default_timeout(self) -> None:
        client = OSVClient()
        assert client._client.timeout.connect == 30.0
        client.close()

    def test_init_custom_timeout(self) -> None:
        client = OSVClient(timeout=10.0)
        assert client._client.timeout.connect == 10.0
        client.close()

    def test_context_manager(self) -> None:
        with OSVClient() as client:
            assert isinstance(client, OSVClient)
        # Client should be closed after exiting context

    def test_close(self) -> None:
        client = OSVClient()
        client.close()
        # Should not raise


class TestQueryVulnerabilities:
    """Tests for query_vulnerabilities method."""

    def test_success_with_vulns(self) -> None:
        with patch("depcheck.osv.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "vulns": [
                    {
                        "id": "GHSA-test-1234",
                        "summary": "Test vulnerability",
                        "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                        "aliases": ["CVE-2024-1234"],
                    }
                ]
            }
            mock_client.post.return_value = mock_response

            client = OSVClient()
            vulns = client.query_vulnerabilities("test-package", "1.0.0")

            assert len(vulns) == 1
            assert vulns[0].vuln_id == "GHSA-test-1234"
            assert vulns[0].summary == "Test vulnerability"
            assert vulns[0].severity == "HIGH"
            assert vulns[0].url == "https://osv.dev/vulnerability/GHSA-test-1234"
            assert vulns[0].aliases == ["CVE-2024-1234"]
            client.close()

    def test_success_empty_vulns(self) -> None:
        with patch("depcheck.osv.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"vulns": []}
            mock_client.post.return_value = mock_response

            client = OSVClient()
            vulns = client.query_vulnerabilities("safe-package", "1.0.0")

            assert vulns == []
            client.close()

    def test_404_returns_empty(self) -> None:
        with patch("depcheck.osv.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_client.post.return_value = mock_response

            client = OSVClient()
            vulns = client.query_vulnerabilities("unknown-package", "1.0.0")

            assert vulns == []
            client.close()

    def test_http_error_returns_empty(self) -> None:
        with patch("depcheck.osv.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            mock_client.post.side_effect = httpx.HTTPError("Connection failed")

            client = OSVClient()
            vulns = client.query_vulnerabilities("test-package", "1.0.0")

            assert vulns == []
            client.close()

    def test_http_status_error_returns_empty(self) -> None:
        with patch("depcheck.osv.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Server error", request=MagicMock(), response=mock_response
            )
            mock_client.post.return_value = mock_response

            client = OSVClient()
            vulns = client.query_vulnerabilities("test-package", "1.0.0")

            assert vulns == []
            client.close()

    def test_correct_payload_sent(self) -> None:
        with patch("depcheck.osv.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"vulns": []}
            mock_client.post.return_value = mock_response

            client = OSVClient()
            client.query_vulnerabilities("my-package", "2.5.1")

            mock_client.post.assert_called_once()
            call_args = mock_client.post.call_args
            assert call_args[0][0] == "https://api.osv.dev/v1/query"
            payload = call_args[1]["json"]
            assert payload["version"] == "2.5.1"
            assert payload["package"]["name"] == "my-package"
            assert payload["package"]["ecosystem"] == "PyPI"
            client.close()


class TestParseVulnerability:
    """Tests for _parse_vulnerability method."""

    def test_parse_minimal_vuln(self) -> None:
        client = OSVClient()
        vuln_data = {
            "id": "GHSA-minimal",
            "summary": "Minimal vulnerability",
        }
        vuln = client._parse_vulnerability(vuln_data)

        assert vuln.vuln_id == "GHSA-minimal"
        assert vuln.summary == "Minimal vulnerability"
        assert vuln.severity == "UNKNOWN"
        assert vuln.url == "https://osv.dev/vulnerability/GHSA-minimal"
        assert vuln.aliases == []
        client.close()

    def test_parse_with_aliases(self) -> None:
        client = OSVClient()
        vuln_data = {
            "id": "GHSA-with-aliases",
            "summary": "Has aliases",
            "aliases": ["CVE-2024-0001", "GHSA-other"],
        }
        vuln = client._parse_vulnerability(vuln_data)

        assert vuln.aliases == ["CVE-2024-0001", "GHSA-other"]
        client.close()

    def test_parse_missing_id_uses_unknown(self) -> None:
        client = OSVClient()
        vuln_data = {"summary": "No ID"}
        vuln = client._parse_vulnerability(vuln_data)

        assert vuln.vuln_id == "UNKNOWN"
        assert vuln.url == "https://osv.dev/vulnerability/UNKNOWN"
        client.close()

    def test_parse_missing_summary_uses_default(self) -> None:
        client = OSVClient()
        vuln_data = {"id": "GHSA-no-summary"}
        vuln = client._parse_vulnerability(vuln_data)

        assert vuln.summary == "No summary available"
        client.close()


class TestExtractSeverity:
    """Tests for _extract_severity method."""

    def test_cvss_high_impact(self) -> None:
        client = OSVClient()
        vuln_data = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        severity = client._extract_severity(vuln_data)
        assert severity == "HIGH"
        client.close()

    def test_cvss_low_impact(self) -> None:
        client = OSVClient()
        vuln_data = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}]}
        severity = client._extract_severity(vuln_data)
        assert severity == "LOW"
        client.close()

    def test_cvss_medium_impact(self) -> None:
        client = OSVClient()
        vuln_data = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}]}
        severity = client._extract_severity(vuln_data)
        assert severity == "MEDIUM"
        client.close()

    def test_cvss_mixed_impact_high_wins(self) -> None:
        client = OSVClient()
        vuln_data = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"}]}
        severity = client._extract_severity(vuln_data)
        assert severity == "HIGH"
        client.close()

    def test_database_specific_severity(self) -> None:
        client = OSVClient()
        vuln_data = {"database_specific": {"severity": "HIGH"}}
        severity = client._extract_severity(vuln_data)
        assert severity == "HIGH"
        client.close()

    def test_database_specific_severity_lowercase(self) -> None:
        client = OSVClient()
        vuln_data = {"database_specific": {"severity": "medium"}}
        severity = client._extract_severity(vuln_data)
        assert severity == "MEDIUM"
        client.close()

    def test_references_severity_fallback(self) -> None:
        client = OSVClient()
        vuln_data = {
            "references": [{"type": "ADVISORY", "url": "https://example.com", "severity": "HIGH"}]
        }
        severity = client._extract_severity(vuln_data)
        assert severity == "MEDIUM"
        client.close()

    def test_unknown_when_no_severity_info(self) -> None:
        client = OSVClient()
        vuln_data = {"id": "GHSA-no-sev"}
        severity = client._extract_severity(vuln_data)
        assert severity == "UNKNOWN"
        client.close()

    def test_multiple_severity_entries_first_cvss_used(self) -> None:
        client = OSVClient()
        vuln_data = {
            "severity": [
                {"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                {"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
            ]
        }
        severity = client._extract_severity(vuln_data)
        assert severity == "HIGH"
        client.close()

    def test_non_cvss_severity_skipped(self) -> None:
        client = OSVClient()
        vuln_data = {"severity": [{"score": "OTHER:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        severity = client._extract_severity(vuln_data)
        assert severity == "UNKNOWN"
        client.close()


class TestOSVClientIntegration:
    """Integration-style tests for OSVClient."""

    def test_multiple_vulns_parsed(self) -> None:
        with patch("depcheck.osv.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "vulns": [
                    {
                        "id": "GHSA-vuln-1",
                        "summary": "First vulnerability",
                        "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                        "aliases": ["CVE-2024-0001"],
                    },
                    {
                        "id": "GHSA-vuln-2",
                        "summary": "Second vulnerability",
                        "database_specific": {"severity": "MEDIUM"},
                        "aliases": [],
                    },
                ]
            }
            mock_client.post.return_value = mock_response

            client = OSVClient()
            vulns = client.query_vulnerabilities("multi-vuln-pkg", "1.0.0")

            assert len(vulns) == 2
            assert vulns[0].vuln_id == "GHSA-vuln-1"
            assert vulns[0].severity == "HIGH"
            assert vulns[1].vuln_id == "GHSA-vuln-2"
            assert vulns[1].severity == "MEDIUM"
            client.close()

    def test_client_reuse(self) -> None:
        """Test that the same client can make multiple queries."""
        with patch("depcheck.osv.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"vulns": []}
            mock_client.post.return_value = mock_response

            client = OSVClient()
            client.query_vulnerabilities("pkg1", "1.0.0")
            client.query_vulnerabilities("pkg2", "2.0.0")
            client.query_vulnerabilities("pkg3", "3.0.0")

            assert mock_client.post.call_count == 3
            client.close()
