"""Unit tests for the sources modules."""

from unittest.mock import MagicMock, patch

from disposablehosts.sources.file import fetch_file_source
from disposablehosts.sources.http import fetch_http_source, fetch_http_source_raw
from disposablehosts.sources.websocket import fetch_websocket_source


class TestFetchFileSource:
    """Tests for fetch_file_source function."""

    @patch("disposablehosts.sources.file.remoteData.fetch_file")
    def test_fetch_file_source(self, mock_fetch_file):
        """Test fetch_file_source delegates to remoteData."""
        mock_fetch_file.return_value = b"example.com\n"

        result = fetch_file_source("domains.txt", ignore_not_exists=True)
        assert result == b"example.com\n"
        mock_fetch_file.assert_called_with("domains.txt", True)

    @patch("disposablehosts.sources.file.remoteData.fetch_file")
    def test_fetch_file_source_default_ignore(self, mock_fetch_file):
        """Test fetch_file_source with default ignore_not_exists=False."""
        mock_fetch_file.return_value = b"example.com\n"

        fetch_file_source("domains.txt")
        mock_fetch_file.assert_called_with("domains.txt", False)


class TestFetchHttpSource:
    """Tests for HTTP source functions."""

    @patch("disposablehosts.sources.http.remoteData.fetch_http")
    def test_fetch_http_source(self, mock_fetch_http):
        """Test fetch_http_source delegates to remoteData."""
        mock_fetch_http.return_value = b'["example.com", "test.org"]'

        result = fetch_http_source("https://api.example.com/domains")
        assert result == b'["example.com", "test.org"]'
        mock_fetch_http.assert_called_once_with(
            "https://api.example.com/domains",
            None,
            None,
            None,
        )

    @patch("disposablehosts.sources.http.remoteData.fetch_http")
    def test_fetch_http_source_with_params(self, mock_fetch_http):
        """Test fetch_http_source with all parameters."""
        mock_fetch_http.return_value = b"content"

        fetch_http_source(
            "https://api.example.com/domains",
            headers={"Accept": "application/json"},
            timeout=10,
            max_retry=5,
        )

        mock_fetch_http.assert_called_once_with(
            "https://api.example.com/domains",
            {"Accept": "application/json"},
            10,
            5,
        )

    @patch("disposablehosts.sources.http.remoteData.fetch_http_raw")
    def test_fetch_http_source_raw(self, mock_fetch_raw):
        """Test fetch_http_source_raw delegates to remoteData."""
        mock_response = MagicMock()
        mock_fetch_raw.return_value = mock_response

        result = fetch_http_source_raw("https://api.example.com/domains")
        assert result == mock_response
        mock_fetch_raw.assert_called_once_with(
            "https://api.example.com/domains",
            None,
            None,
            None,
        )


class TestFetchWebsocketSource:
    """Tests for WebSocket source function."""

    @patch("disposablehosts.sources.websocket.remoteData.fetch_ws")
    def test_fetch_websocket_source(self, mock_fetch_ws):
        """Test fetch_websocket_source delegates to remoteData."""
        mock_fetch_ws.return_value = b"domain1.com,domain2.com"

        result = fetch_websocket_source("wss://example.com/ws")
        assert result == b"domain1.com,domain2.com"
        mock_fetch_ws.assert_called_once_with("wss://example.com/ws")
