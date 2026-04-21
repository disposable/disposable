"""Unit tests for remote data fetching utilities."""

from pathlib import Path

from disposablehosts.remote_data import remoteData


class _DummyResponse:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload


class TestRemoteData:
    """Tests for remoteData static helpers."""

    def test_fetch_file_reads_bytes(self, tmp_path: Path):
        """fetch_file should return file contents as bytes."""
        target = tmp_path / "domains.txt"
        target.write_text("example.com\n", encoding="utf-8")
        assert remoteData.fetch_file(str(target)) == b"example.com\n"

    def test_fetch_file_ignore_errors(self, tmp_path: Path):
        """fetch_file should return empty bytes when ignore_errors is enabled."""
        missing = tmp_path / "missing.txt"
        assert remoteData.fetch_file(str(missing), ignore_errors=True) == b""

    def test_fetch_http_returns_content(self, monkeypatch):
        """fetch_http should return payload read from raw response."""

        def _fake_fetch_http_raw(*_args, **_kwargs):
            return _DummyResponse(b"payload")

        monkeypatch.setattr(remoteData, "fetch_http_raw", _fake_fetch_http_raw)
        assert remoteData.fetch_http("https://example.test") == b"payload"

    def test_fetch_http_returns_empty_on_failure(self, monkeypatch):
        """fetch_http should return empty bytes if raw request failed."""

        def _fake_fetch_http_raw(*_args, **_kwargs):
            return None

        monkeypatch.setattr(remoteData, "fetch_http_raw", _fake_fetch_http_raw)
        assert remoteData.fetch_http("https://example.test") == b""
