"""Unit tests for the WebSocket preprocessing module."""

from disposablehosts.preprocessing.websocket import preprocess_websocket


class TestPreprocessWebsocket:
    """Tests for preprocess_websocket function."""

    def test_preprocess_websocket_with_d_prefix(self):
        """Test preprocessing WebSocket data with D prefix."""
        data = b"Ddomain1.com,domain2.com,domain3.com"
        result = preprocess_websocket(data)
        assert result == ["domain1.com", "domain2.com", "domain3.com"]

    def test_preprocess_websocket_multiple_lines_with_d(self):
        """Test preprocessing with multiple lines, only first D line processed."""
        data = b"Header info\nDdomain1.com,domain2.com\nFooter info"
        result = preprocess_websocket(data)
        assert result == ["domain1.com", "domain2.com"]

    def test_preprocess_websocket_no_d_prefix(self):
        """Test preprocessing WebSocket data without D prefix returns empty."""
        data = b"domain1.com,domain2.com"
        result = preprocess_websocket(data)
        assert result == []

    def test_preprocess_websocket_empty_data(self):
        """Test preprocessing empty WebSocket data."""
        data = b""
        result = preprocess_websocket(data)
        assert result == []

    def test_preprocess_websocket_whitespace_lines(self):
        """Test preprocessing WebSocket data with empty/whitespace lines."""
        data = b"\n\nDexample.com\n\n"
        result = preprocess_websocket(data)
        assert result == ["example.com"]

    def test_preprocess_websocket_single_domain(self):
        """Test preprocessing with single domain."""
        data = b"Dexample.com"
        result = preprocess_websocket(data)
        assert result == ["example.com"]

    def test_preprocess_websocket_d_not_at_start(self):
        """Test that D must be at the start of a line."""
        data = b"XDexample.com"
        result = preprocess_websocket(data)
        assert result == []
