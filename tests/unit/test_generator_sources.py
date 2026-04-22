"""Source handling tests for the generator module.

Tests cover:
- Source fetching (_fetch_data) for various source types
- Source listing and skipping
- Custom source handlers (tempmailo)
"""

from unittest.mock import MagicMock, patch

from disposablehosts.generator import disposableHostGenerator


class TestFetchData:
    """Tests for _fetch_data method."""

    @patch("disposablehosts.generator.fetch_file_source")
    def test_fetch_data_file(self, mock_fetch):
        """Test fetching file source."""
        mock_fetch.return_value = b"example.com\n"
        gen = disposableHostGenerator()
        source = {"type": "file", "src": "test.txt"}
        result = gen._fetch_data(source)
        assert result == b"example.com\n"

    @patch("disposablehosts.generator.fetch_websocket_source")
    def test_fetch_data_ws(self, mock_fetch):
        """Test fetching websocket source."""
        mock_fetch.return_value = b"domain1.com,domain2.com"
        gen = disposableHostGenerator()
        source = {"type": "ws", "src": "wss://example.com/ws"}
        result = gen._fetch_data(source)
        assert result == b"domain1.com,domain2.com"

    @patch("disposablehosts.generator.fetch_http_source")
    def test_fetch_data_http(self, mock_fetch):
        """Test fetching HTTP source."""
        mock_fetch.return_value = b'["example.com"]'
        gen = disposableHostGenerator()
        source = {"type": "json", "src": "https://api.example.com"}
        result = gen._fetch_data(source)
        assert result == b'["example.com"]'


class TestFetchDataExtended:
    """Extended tests for _fetch_data method."""

    def test_fetch_data_custom_source(self):
        """Test fetching custom source type calls _process method."""
        gen = disposableHostGenerator()
        # Add a mock _process method
        gen._processTestSource = lambda: b"custom data"  # type: ignore[attr-defined]

        source = {"type": "custom", "src": "TestSource"}
        result = gen._fetch_data(source)

        assert result == b"custom data"

    @patch("disposablehosts.generator.fetch_file_source")
    def test_fetch_data_whitelist_file(self, mock_fetch):
        """Test fetching whitelist_file source."""
        mock_fetch.return_value = b"example.com\n"
        gen = disposableHostGenerator()
        source = {"type": "whitelist_file", "src": "whitelist.txt", "ignore_not_exists": True}
        result = gen._fetch_data(source)

        assert result == b"example.com\n"
        mock_fetch.assert_called_with("whitelist.txt", True)

    @patch("disposablehosts.generator.fetch_file_source")
    def test_fetch_data_greylist_file(self, mock_fetch):
        """Test fetching greylist_file source."""
        mock_fetch.return_value = b"grey.com\n"
        gen = disposableHostGenerator()
        source = {"type": "greylist_file", "src": "greylist.txt", "ignore_not_exists": False}
        result = gen._fetch_data(source)

        assert result == b"grey.com\n"
        mock_fetch.assert_called_with("greylist.txt", False)

    @patch("disposablehosts.generator.fetch_http_source")
    def test_fetch_data_html_with_headers(self, mock_fetch):
        """Test fetching HTML source uses correct headers."""
        mock_fetch.return_value = b"<html></html>"
        gen = disposableHostGenerator()
        source = {"type": "html", "src": "https://example.com", "timeout": 5}
        result = gen._fetch_data(source)

        assert result == b"<html></html>"
        # HTML type should not have json headers
        call_args = mock_fetch.call_args
        headers = call_args[1].get("headers", call_args[0][1] if len(call_args[0]) > 1 else {})
        assert "Accept" not in headers or "json" not in headers.get("Accept", "")


class TestFetchSources:
    """Tests for _fetch_sources method."""

    @patch.object(disposableHostGenerator, "process")
    def test_fetch_sources_with_src_filter(self, mock_process):
        """Test fetch sources with src_filter."""
        gen = disposableHostGenerator({"src_filter": "test_source"})
        gen._fetch_sources()
        assert mock_process.called is False

    @patch.object(disposableHostGenerator, "_should_skip_source")
    @patch.object(disposableHostGenerator, "process")
    def test_fetch_sources_skip_disabled(self, mock_process, mock_skip):
        """Test fetch sources with disabled source."""
        mock_skip.return_value = True
        gen = disposableHostGenerator()
        gen._fetch_sources()


class TestShouldSkipSource:
    """Tests for _should_skip_source method."""

    def test_should_skip_by_src_filter(self):
        """Test skipping by src_filter."""
        gen = disposableHostGenerator({"src_filter": "specific_source"})
        source = {"src": "other_source"}
        assert gen._should_skip_source(source) is True

    def test_should_not_skip(self):
        """Test not skipping valid source."""
        gen = disposableHostGenerator()
        source = {"src": "valid_source"}
        assert gen._should_skip_source(source) is False

    def test_should_skip_by_skip_src(self):
        """Test skipping by skip_src list."""
        gen = disposableHostGenerator({"skip_src": ["skip_me"]})
        source = {"src": "skip_me"}
        assert gen._should_skip_source(source) is True


class TestShouldSkipSourceExtended:
    """Extended tests for _should_skip_source method with type coercion."""

    def test_skip_src_not_list(self):
        """Test that non-list skip_src is converted to empty list."""
        gen = disposableHostGenerator({"skip_src": "not_a_list"})
        source = {"src": "some_source"}
        # Should not raise error and should not skip
        result = gen._should_skip_source(source)
        assert result is False

    def test_should_skip_src_filter_no_match(self):
        """Test that src_filter skips non-matching sources."""
        gen = disposableHostGenerator({"src_filter": "specific_source"})
        source = {"src": "other_source"}
        result = gen._should_skip_source(source)
        assert result is True

    def test_should_not_skip_whitelist_with_filter(self):
        """Test that whitelist/greylist sources are not skipped by src_filter."""
        gen = disposableHostGenerator({"src_filter": "specific_source"})
        source = {"src": "whitelist_file"}
        result = gen._should_skip_source(source)
        assert result is False


class TestProcessTempmailo:
    """Tests for _processTempmailo custom source handler."""

    @patch("disposablehosts.sources.http.fetch_http_source_raw")
    @patch("disposablehosts.generator.fetch_http_source")
    def test_process_tempmailo_success(self, mock_fetch_http, mock_fetch_raw):
        """Test successful tempmailo.com domain extraction."""
        # Mock initial response with token and cookies
        mock_response = MagicMock()
        mock_response.headers = {"set-cookie": "session=abc123; Path=/"}
        mock_response.read.return_value = b'<input name="__RequestVerificationToken" value="test_token_123" />'
        mock_fetch_raw.return_value = mock_response

        # Mock secondary response with domains
        mock_fetch_http.return_value = b"user1@domain1.com\nuser2@domain2.com"

        gen = disposableHostGenerator()
        result = gen._processTempmailo()

        assert result == ["domain1.com", "domain2.com"]
        mock_fetch_raw.assert_called_once_with("https://tempmailo.com/")

    @patch("disposablehosts.sources.http.fetch_http_source_raw")
    def test_process_tempmailo_no_token(self, mock_fetch_raw):
        """Test tempmailo when RequestVerificationToken is missing."""
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.read.return_value = b"<html>No token here</html>"
        mock_fetch_raw.return_value = mock_response

        gen = disposableHostGenerator()
        result = gen._processTempmailo()

        assert result is None

    @patch("disposablehosts.sources.http.fetch_http_source_raw")
    def test_process_tempmailo_none_response(self, mock_fetch_raw):
        """Test tempmailo when initial request fails."""
        mock_fetch_raw.return_value = None

        gen = disposableHostGenerator()
        result = gen._processTempmailo()

        assert result is None

    @patch("disposablehosts.sources.http.fetch_http_source_raw")
    @patch("disposablehosts.generator.fetch_http_source")
    def test_process_tempmailo_secondary_request_fails(self, mock_fetch_http, mock_fetch_raw):
        """Test tempmailo when secondary request returns empty."""
        mock_response = MagicMock()
        mock_response.headers = {"set-cookie": "session=abc123; Path=/"}
        mock_response.read.return_value = b'<input name="__RequestVerificationToken" value="token123" />'
        mock_fetch_raw.return_value = mock_response

        mock_fetch_http.return_value = b""

        gen = disposableHostGenerator()
        result = gen._processTempmailo()

        assert result is None

    @patch("disposablehosts.sources.http.fetch_http_source_raw")
    @patch("disposablehosts.generator.fetch_http_source")
    def test_process_tempmailo_skips_underscore_cookies(self, mock_fetch_http, mock_fetch_raw):
        """Test that cookies starting with __ are skipped."""
        mock_response = MagicMock()
        mock_response.headers = {"set-cookie": "__cfduid=xyz; Path=/, session=abc123; Path=/, __session=ignored; Path=/"}
        mock_response.read.return_value = b'<input name="__RequestVerificationToken" value="token123" />'
        mock_fetch_raw.return_value = mock_response

        mock_fetch_http.return_value = b"user@example.com"

        gen = disposableHostGenerator()
        gen._processTempmailo()

        # Verify the call was made with correct headers
        call_args = mock_fetch_http.call_args
        headers = call_args[1].get("headers", call_args[0][1] if len(call_args[0]) > 1 else {})
        assert "cookie" in headers
        assert "__cfduid" not in headers["cookie"]
        assert "__session" not in headers["cookie"]
