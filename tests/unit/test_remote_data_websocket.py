"""Tests for WebSocket-based remote data fetching.

Tests for WebSocket connections with message handling.
"""

from unittest.mock import MagicMock, patch

from disposablehosts.remote_data import remoteData


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
