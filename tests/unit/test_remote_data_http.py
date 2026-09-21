"""Tests for HTTP-based remote data fetching.

Tests for HTTP/HTTPS requests with retries, headers, and timeouts.
"""

from unittest.mock import MagicMock, patch

from disposablehosts.remote_data import remoteData


class _DummyResponse:
    """Dummy response class for testing."""

    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload


class TestFetchHttp:
    """Tests for fetch_http method."""

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

    @patch("disposablehosts.remote_data.remoteData.fetch_http_raw")
    def test_fetch_http_success(self, mock_fetch_raw):
        """Test successful HTTP fetch."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"content"
        mock_fetch_raw.return_value = mock_response

        result = remoteData.fetch_http("https://example.com")
        assert result == b"content"

    @patch("disposablehosts.remote_data.remoteData.fetch_http_raw")
    def test_fetch_http_failure(self, mock_fetch_raw):
        """Test HTTP fetch when raw fetch fails."""
        mock_fetch_raw.return_value = None

        result = remoteData.fetch_http("https://example.com")
        assert result == b""

    @patch("disposablehosts.remote_data.remoteData.fetch_flaresolverr")
    @patch("disposablehosts.remote_data.remoteData.fetch_http_raw")
    def test_fetch_http_falls_back_to_flaresolverr_on_challenge(self, mock_fetch_raw, mock_flare, monkeypatch):
        """fetch_http retries via FlareSolverr when Cloudflare challenge is detected."""
        monkeypatch.setenv("FLARESOLVERR_URL", "http://127.0.0.1:8191")
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.read.return_value = b"<html><title>Just a moment...</title>challenges.cloudflare.com</html>"
        mock_fetch_raw.return_value = mock_response
        mock_flare.return_value = b"solved content"

        result = remoteData.fetch_http("https://example.com")
        assert result == b"solved content"
        mock_flare.assert_called_once_with("https://example.com")

    @patch("disposablehosts.remote_data.remoteData.fetch_flaresolverr")
    @patch("disposablehosts.remote_data.remoteData.fetch_http_raw")
    def test_fetch_http_returns_challenge_body_without_flaresolverr(self, mock_fetch_raw, mock_flare, monkeypatch):
        """fetch_http returns the challenge body when FLARESOLVERR_URL is unset."""
        monkeypatch.delenv("FLARESOLVERR_URL", raising=False)
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.read.return_value = b"Just a moment challenges.cloudflare.com"
        mock_fetch_raw.return_value = mock_response

        result = remoteData.fetch_http("https://example.com")
        assert result == b"Just a moment challenges.cloudflare.com"
        mock_flare.assert_not_called()

    @patch("disposablehosts.remote_data.remoteData.fetch_http_raw")
    def test_fetch_http_forwards_parameters(self, mock_fetch_raw):
        """Test fetch_http forwards parameters to fetch_http_raw."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"content"
        mock_fetch_raw.return_value = mock_response

        remoteData.fetch_http("https://example.com", headers={"X-Test": "value"}, timeout=10, max_retry=5)

        mock_fetch_raw.assert_called_once_with(
            "https://example.com",
            {"X-Test": "value"},
            10,
            5,
        )


class TestFetchHttpRaw:
    """Tests for fetch_http_raw method."""

    @patch("disposablehosts.remote_data.httpx.Client")
    def test_fetch_http_raw_success(self, mock_client_class):
        """Test successful raw HTTP fetch."""
        mock_response = MagicMock()
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_class.return_value = mock_client

        result = remoteData.fetch_http_raw("https://example.com")
        assert result == mock_response
        mock_client.get.assert_called_once()

    @patch("disposablehosts.remote_data.httpx.Client")
    def test_fetch_http_raw_with_headers(self, mock_client_class):
        """Test raw HTTP fetch with custom headers."""
        mock_response = MagicMock()
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_class.return_value = mock_client

        custom_headers = {"X-Custom": "value"}
        remoteData.fetch_http_raw("https://example.com", headers=custom_headers)

        call_args = mock_client.get.call_args
        assert "X-Custom" in call_args[1]["headers"]

    @patch("disposablehosts.remote_data.httpx.Client")
    def test_fetch_http_raw_with_timeout(self, mock_client_class):
        """Test raw HTTP fetch with custom timeout."""
        mock_response = MagicMock()
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_class.return_value = mock_client

        remoteData.fetch_http_raw("https://example.com", timeout=10)

        call_args = mock_client.get.call_args
        assert call_args[1]["timeout"] == 10

    @patch("disposablehosts.remote_data.httpx.Client")
    @patch("disposablehosts.remote_data.time.sleep")
    def test_fetch_http_raw_retry_on_timeout(self, mock_sleep, mock_client_class):
        """Test raw HTTP fetch retries on timeout."""
        mock_client = MagicMock()
        mock_client.get.side_effect = [
            Exception("The read operation timed out"),
            MagicMock(),
        ]
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_class.return_value = mock_client

        result = remoteData.fetch_http_raw("https://example.com", max_retry=2)
        assert result is not None
        assert mock_client.get.call_count == 2
        mock_sleep.assert_called_once_with(1)

    @patch("disposablehosts.remote_data.httpx.Client")
    def test_fetch_http_raw_max_retry_exceeded(self, mock_client_class):
        """Test raw HTTP fetch fails after max retries."""
        mock_client = MagicMock()
        # Error must match RETRY_ERRORS_RE pattern to trigger retry
        mock_client.get.side_effect = Exception("The read operation timed out")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_class.return_value = mock_client

        result = remoteData.fetch_http_raw("https://example.com", max_retry=2)
        assert result is None
        assert mock_client.get.call_count == 2

    @patch("disposablehosts.remote_data.httpx.Client")
    def test_fetch_http_raw_default_headers(self, mock_client_class):
        """Test raw HTTP fetch sets default headers."""
        mock_response = MagicMock()
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_class.return_value = mock_client

        remoteData.fetch_http_raw("https://example.com")

        call_args = mock_client.get.call_args
        headers = call_args[1]["headers"]
        assert "User-Agent" in headers
        assert "Mozilla" in headers["User-Agent"]
        assert "Accept" in headers

    @patch("disposablehosts.remote_data.httpx.Client")
    def test_fetch_http_raw_http2_enabled(self, mock_client_class):
        """Test raw HTTP fetch uses HTTP/2."""
        mock_client = MagicMock()
        mock_client.get.return_value = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_class.return_value = mock_client

        remoteData.fetch_http_raw("https://example.com")

        # Verify Client was created with http2=True
        call_kwargs = mock_client_class.call_args[1]
        assert call_kwargs.get("http2") is True
        assert call_kwargs.get("verify") is False


class TestFetchFlareSolverr:
    """Tests for the FlareSolverr fallback helper."""

    @patch("disposablehosts.remote_data.httpx.post")
    def test_fetch_flaresolverr_get(self, mock_post, monkeypatch):
        """GET request returns the solved response body."""
        monkeypatch.setenv("FLARESOLVERR_URL", "http://127.0.0.1:8191")
        mock_res = MagicMock()
        mock_res.json.return_value = {"status": "ok", "solution": {"status": 200, "response": "<html>ok</html>"}}
        mock_post.return_value = mock_res

        result = remoteData.fetch_flaresolverr("https://example.com")
        assert result == b"<html>ok</html>"
        payload = mock_post.call_args[1]["json"]
        assert payload["cmd"] == "request.get"
        assert "postData" not in payload

    @patch("disposablehosts.remote_data.httpx.post")
    def test_fetch_flaresolverr_post(self, mock_post, monkeypatch):
        """POST request passes postData and uses request.post."""
        monkeypatch.setenv("FLARESOLVERR_URL", "http://127.0.0.1:8191")
        mock_res = MagicMock()
        mock_res.json.return_value = {
            "status": "ok",
            "solution": {"status": 200, "response": '<pre>{"mailbox":"logalew991@airychen.com"}</pre>'},
        }
        mock_post.return_value = mock_res

        result = remoteData.fetch_flaresolverr("https://web2.temp-mail.org/mailbox", post_data="{}")
        assert b"airychen.com" in result
        payload = mock_post.call_args[1]["json"]
        assert payload["cmd"] == "request.post"
        assert payload["postData"] == "{}"

    @patch("disposablehosts.remote_data.httpx.post")
    def test_fetch_flaresolverr_no_url_env(self, mock_post, monkeypatch):
        """Returns empty bytes when FLARESOLVERR_URL is unset."""
        monkeypatch.delenv("FLARESOLVERR_URL", raising=False)
        assert remoteData.fetch_flaresolverr("https://example.com") == b""
        mock_post.assert_not_called()


class TestTempMailOrgProcessor:
    """Tests for the temp-mail.org FlareSolverr scraper."""

    def test_parses_mailbox_domain(self):
        from disposablehosts.generator import disposableHostGenerator

        gen = disposableHostGenerator(options={"whitelist": "whitelist.txt"}, out_file="/tmp/domains-test")
        with patch("disposablehosts.generator.remoteData.fetch_flaresolverr") as mock_fs, patch("disposablehosts.generator.time.sleep"):
            mock_fs.return_value = b'<html><body><pre>{"token":"x","mailbox":"logalew991@airychen.com"}</pre></body></html>'
            assert gen._processTempMailOrg() == ["airychen.com"]
            assert mock_fs.call_count == 5

    def test_collects_multiple_domains(self):
        from disposablehosts.generator import disposableHostGenerator

        gen = disposableHostGenerator(options={"whitelist": "whitelist.txt"}, out_file="/tmp/domains-test")
        bodies = [
            b'{"mailbox":"a@airychen.com"}',
            b'{"mailbox":"b@airychen.com"}',
            b'{"mailbox":"c@findize.com"}',
            b"",
        ]
        with patch("disposablehosts.generator.remoteData.fetch_flaresolverr") as mock_fs, patch("disposablehosts.generator.time.sleep"):
            mock_fs.side_effect = bodies
            assert gen._processTempMailOrg() == ["airychen.com", "findize.com"]
            assert mock_fs.call_count == 4

    def test_returns_none_without_mailbox(self):
        from disposablehosts.generator import disposableHostGenerator

        gen = disposableHostGenerator(options={"whitelist": "whitelist.txt"}, out_file="/tmp/domains-test")
        with patch("disposablehosts.generator.remoteData.fetch_flaresolverr") as mock_fs:
            mock_fs.return_value = b"{}"
            assert gen._processTempMailOrg() is None
