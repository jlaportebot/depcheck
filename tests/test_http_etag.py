"""Tests for depcheck.http ETag / conditional request helpers."""

from __future__ import annotations

from unittest.mock import MagicMock

from depcheck.http import ETagStore, conditional_get_json


def _make_response(status_code: int, body: dict, etag: str | None = None) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = body
    headers = {"etag": etag} if etag is not None else {}
    response.headers.get.side_effect = lambda name, default=None: headers.get(name.lower(), default)
    return response


class TestETagStore:
    def test_get_missing_returns_none(self) -> None:
        store = ETagStore()
        assert store.get("https://example.com/x") is None

    def test_set_then_get_returns_etag(self) -> None:
        store = ETagStore()
        store.set("https://example.com/x", '"abc"')
        assert store.get("https://example.com/x") == '"abc"'


class TestConditionalGetJSON:
    def test_200_returns_payload_and_stores_etag(self) -> None:
        store = ETagStore()
        client = MagicMock()
        client.get.return_value = _make_response(200, {"name": "requests"}, '"abc"')

        payload, etag, status = conditional_get_json(
            client, "https://pypi.org/pypi/requests/json", store
        )

        assert status == 200
        assert payload == {"name": "requests"}
        assert etag == '"abc"'
        assert store.get("https://pypi.org/pypi/requests/json") == '"abc"'
        client.get.assert_called_once()

    def test_304_returns_none_and_keeps_etag(self) -> None:
        store = ETagStore()
        store.set("https://pypi.org/pypi/requests/json", '"abc"')
        client = MagicMock()
        client.get.return_value = _make_response(304, {}, '"abc"')

        payload, etag, status = conditional_get_json(
            client, "https://pypi.org/pypi/requests/json", store
        )

        assert status == 304
        assert payload is None
        assert etag == '"abc"'
        # No payload to parse on a not-modified response.
        client.get.return_value.json.assert_not_called()

    def test_404_returns_none_without_raising(self) -> None:
        store = ETagStore()
        client = MagicMock()
        client.get.return_value = _make_response(404, {})

        payload, etag, status = conditional_get_json(
            client, "https://pypi.org/pypi/does-not-exist/json", store
        )

        assert status == 404
        assert payload is None
        assert etag is None

    def test_no_etag_header_does_not_store(self) -> None:
        store = ETagStore()
        client = MagicMock()
        client.get.return_value = _make_response(200, {"name": "requests"})

        payload, etag, status = conditional_get_json(
            client, "https://pypi.org/pypi/requests/json", store
        )

        assert status == 200
        assert payload == {"name": "requests"}
        assert etag is None
        assert store.get("https://pypi.org/pypi/requests/json") is None
