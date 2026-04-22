"""Extended unit tests for remote data fetching utilities."""

from unittest.mock import MagicMock, patch


from disposablehosts.remote_data import remoteData


class _DummyResponse:
    """Dummy response class for testing."""

    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload


class TestFetchWS:
    """Tests for fetch_ws method."""

    @patch("disposablehosts.remote_data.create_connection")
    def test_fetch_ws_success(self, mock_create_connection):
        """Test successful WebSocket fetch."""
        mock_ws = MagicMock()
        mock_ws.recv.side_effect = ["msg1", "msg2", "msg3"]
        mock_create_connection.return_value = mock_ws

        result = remoteData.fetch_ws("wss://example.com/ws")
        assert result == b"msg1\nmsg2\nmsg3"
        mock_ws.close.assert_called_once()

    @patch("disposablehosts.remote_data.create_connection")
    def test_fetch_ws_bytes_response(self, mock_create_connection):
        """Test WebSocket fetch with bytes response."""
        mock_ws = MagicMock()
        mock_ws.recv.side_effect = [b"msg1", b"msg2", b"msg3"]
        mock_create_connection.return_value = mock_ws

        result = remoteData.fetch_ws("wss://example.com/ws")
        assert result == b"msg1\nmsg2\nmsg3"

    @patch("disposablehosts.remote_data.create_connection")
    def test_fetch_ws_exception(self, mock_create_connection):
        """Test WebSocket fetch with connection error."""
        mock_create_connection.side_effect = Exception("Connection failed")

        result = remoteData.fetch_ws("wss://example.com/ws")
        assert result == b""

    @patch("disposablehosts.remote_data.create_connection")
    def test_fetch_ws_partial_messages(self, mock_create_connection):
        """Test WebSocket fetch with fewer than 3 messages."""
        mock_ws = MagicMock()
        # Simulate connection closing after 2 messages
        mock_ws.recv.side_effect = ["msg1", "msg2", Exception("Connection closed")]
        mock_create_connection.return_value = mock_ws

        result = remoteData.fetch_ws("wss://example.com/ws")
        # Exception handling returns empty bytes
        assert result == b""


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


class TestFetchHttp:
    """Tests for fetch_http method."""

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


class TestFetchFile:
    """Tests for fetch_file method."""

    def test_fetch_file_success(self, tmp_path):
        """Test successful file fetch."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("example.com\n", encoding="utf-8")

        result = remoteData.fetch_file(str(test_file))
        assert result == b"example.com\n"

    def test_fetch_file_not_found_raises(self, tmp_path):
        """Test file fetch raises error when not found."""
        missing_file = tmp_path / "missing.txt"

        with pytest.raises(FileNotFoundError):
            remoteData.fetch_file(str(missing_file))

    def test_fetch_file_not_found_ignore_errors(self, tmp_path):
        """Test file fetch returns empty bytes when ignoring errors."""
        missing_file = tmp_path / "missing.txt"

        result = remoteData.fetch_file(str(missing_file), ignore_errors=True)
        assert result == b""

    @patch("builtins.open")
    def test_fetch_file_io_error(self, mock_open):
        """Test file fetch handles IO error."""
        mock_open.side_effect = IOError("Permission denied")

        with pytest.raises(IOError):
            remoteData.fetch_file("/some/file.txt")

    @patch("builtins.open")
    def test_fetch_file_io_error_ignore_errors(self, mock_open):
        """Test file fetch handles IO error with ignore_errors."""
        mock_open.side_effect = IOError("Permission denied")

        result = remoteData.fetch_file("/some/file.txt", ignore_errors=True)
        assert result == b""


import pytest
