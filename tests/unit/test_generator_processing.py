"""Data processing tests for the generator module.

Tests cover:
- Preprocessing data (_preprocess_data)
- Postprocessing data (_postprocess_data)
- Scrape retry logic
- Fallback domain extraction
"""

import logging
from unittest.mock import patch

from disposablehosts.generator import disposableHostGenerator


class TestPreprocessData:
    """Tests for _preprocess_data method."""

    def test_preprocess_returns_list(self):
        """Test that list data is returned as-is."""
        gen = disposableHostGenerator()
        source = {"type": "json"}
        result = gen._preprocess_data(source, ["domain1.com", "domain2.com"])
        assert result == ["domain1.com", "domain2.com"]

    def test_preprocess_sha1(self):
        """Test SHA1 preprocessing adds to sha1 set."""
        gen = disposableHostGenerator()
        gen.sha1 = set()
        source = {"type": "sha1"}
        data = b"a" * 40 + b"\n" + b"b" * 40 + b"\n"
        result = gen._preprocess_data(source, data)
        assert result == []
        assert len(gen.sha1) == 2

    def test_preprocess_websocket(self):
        """Test WebSocket preprocessing."""
        gen = disposableHostGenerator()
        source = {"type": "ws"}
        data = b"Ddomain1.com,domain2.com"
        result = gen._preprocess_data(source, data)
        assert result == ["domain1.com", "domain2.com"]

    def test_preprocess_json(self):
        """Test JSON preprocessing."""
        gen = disposableHostGenerator()
        source = {"type": "json", "encoding": "utf-8"}
        data = b'["example.com", "test.org"]'
        result = gen._preprocess_data(source, data)
        assert result == ["example.com", "test.org"]

    def test_preprocess_file_types(self):
        """Test file type preprocessing."""
        gen = disposableHostGenerator()
        for fmt in ["whitelist", "list", "file", "whitelist_file", "greylist", "greylist_file"]:
            source = {"type": fmt, "encoding": "utf-8"}
            data = b"# Comment\nexample.com\n\ntest.org\n"
            result = gen._preprocess_data(source, data)
            assert result == ["example.com", "test.org"], f"Failed for format: {fmt}"


class TestPreprocessDataExtended:
    """Extended tests for _preprocess_data with custom encoding."""

    def test_preprocess_html_with_custom_encoding(self):
        """Test HTML preprocessing with custom encoding."""
        gen = disposableHostGenerator()
        source = {"type": "html", "encoding": "iso-8859-1"}
        data = b"<option>example.com</option>"
        result = gen._preprocess_data(source, data)

        # Should process without error
        assert isinstance(result, list)

    def test_preprocess_json_with_custom_encoding(self):
        """Test JSON preprocessing with custom encoding."""
        gen = disposableHostGenerator()
        source = {"type": "json", "encoding": "utf-8"}
        data = b'["example.com"]'
        result = gen._preprocess_data(source, data)

        assert result == ["example.com"]


class TestPostprocessData:
    """Tests for _postprocess_data method."""

    def test_postprocess_whitelist(self):
        """Test postprocessing whitelist source."""
        gen = disposableHostGenerator()
        source = {"type": "whitelist", "src": "whitelist.txt"}
        data = b"example.com\ntest.org"
        lines = ["example.com", "test.org"]
        result = gen._postprocess_data(source, data, lines)
        assert result is True
        assert "example.com" in gen.skip
        assert "test.org" in gen.skip

    def test_postprocess_greylist(self):
        """Test postprocessing greylist source."""
        gen = disposableHostGenerator()
        source = {"type": "greylist", "src": "greylist.txt"}
        data = b"example.com\ntest.org"
        lines = ["example.com", "test.org"]
        result = gen._postprocess_data(source, data, lines)
        assert result is True
        assert "example.com" in gen.grey
        assert "test.org" in gen.grey

    def test_postprocess_with_domains(self):
        """Test postprocessing with valid domains."""
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        data = b"example.com\ntest.org"
        lines = ["example.com", "test.org"]
        result = gen._postprocess_data(source, data, lines)
        assert result == (2, 2)
        assert "example.com" in gen.domains
        assert "test.org" in gen.domains

    def test_postprocess_with_scrape(self):
        """Test postprocessing with scrape option."""
        gen = disposableHostGenerator()
        source = {"type": "html", "src": "https://example.com", "scrape": True}
        data = b"example.com\ntest.org"
        lines = ["example.com", "test.org"]
        result = gen._postprocess_data(source, data, lines)
        assert result == (2, 2)
        assert "example.com" in gen.scrape


class TestPostprocessDataExtended:
    """Extended tests for _postprocess_data method."""

    def test_postprocess_with_sha1_type(self):
        """Test postprocessing sha1 type adds to skip set."""
        gen = disposableHostGenerator()
        source = {"type": "sha1", "src": "hashes.txt"}
        # Use actual domain format that passes validation
        data = b"example.com\n"
        lines = ["example.com"]

        result = gen._postprocess_data(source, data, lines)

        assert result is True
        assert "example.com" in gen.skip

    def test_postprocess_no_valid_domains_logs_warning(self, caplog):
        """Test that warning is logged when no valid domains found."""
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        data = b"!!!invalid!!!\n@@@not_a_domain@@@"
        lines = ["!!!invalid!!!", "@@@not_a_domain@@@"]

        with caplog.at_level(logging.WARNING):
            result = gen._postprocess_data(source, data, lines)

        assert result is False
        assert "No results for source" in caplog.text


class TestProcessSource:
    """Tests for process method."""

    @patch.object(disposableHostGenerator, "_fetch_data")
    @patch.object(disposableHostGenerator, "_preprocess_data")
    @patch.object(disposableHostGenerator, "_postprocess_data")
    def test_process_success(self, mock_post, mock_pre, mock_fetch):
        """Test successful processing."""
        mock_fetch.return_value = b"data"
        mock_pre.return_value = ["example.com"]
        mock_post.return_value = (1, 1)
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        result = gen.process(source)
        assert result is True

    @patch.object(disposableHostGenerator, "_fetch_data")
    def test_process_fetch_none(self, mock_fetch):
        """Test processing when fetch returns None."""
        mock_fetch.return_value = None
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        result = gen.process(source)
        assert result is False

    @patch.object(disposableHostGenerator, "_fetch_data")
    @patch.object(disposableHostGenerator, "_preprocess_data")
    def test_process_preprocess_none(self, mock_pre, mock_fetch):
        """Test processing when preprocess returns None."""
        mock_fetch.return_value = b"data"
        mock_pre.return_value = None
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        result = gen.process(source)
        assert result is False


class TestScrapeRetryLogic:
    """Tests for scrape retry logic in process method."""

    @patch.object(disposableHostGenerator, "_fetch_data")
    @patch.object(disposableHostGenerator, "_preprocess_data")
    @patch.object(disposableHostGenerator, "_postprocess_data")
    def test_scrape_disabled_by_option(self, mock_post, mock_pre, mock_fetch):
        """Test skip_scrape option disables scraping."""
        mock_fetch.return_value = b"data"
        mock_pre.return_value = ["domain1.com"]
        mock_post.return_value = (1, 1)

        gen = disposableHostGenerator({"skip_scrape": True})
        source = {"type": "html", "src": "https://example.com", "scrape": True}
        result = gen.process(source)

        assert result is True
        # Verify scrape was disabled on the source
        assert source.get("scrape") is False

    @patch("disposablehosts.generator.time.sleep")
    @patch.object(disposableHostGenerator, "_fetch_data")
    @patch.object(disposableHostGenerator, "_preprocess_data")
    @patch.object(disposableHostGenerator, "_postprocess_data")
    def test_scrape_with_success(self, mock_post, mock_pre, mock_fetch, mock_sleep):
        """Test scrape with successful processing - exits loop by returning True (bool)."""
        mock_fetch.return_value = b"data"
        mock_pre.return_value = ["domain1.com"]

        # First call returns tuple (processed, found), second call returns True (bool) to exit loop
        mock_post.side_effect = [(1, 1), True]

        gen = disposableHostGenerator()
        source = {"type": "html", "src": "https://example.com", "scrape": True, "timeout": 0.01}
        result = gen.process(source)

        assert result is True
        assert mock_post.call_count >= 1

    @patch("disposablehosts.generator.time.sleep")
    @patch.object(disposableHostGenerator, "_fetch_data")
    @patch.object(disposableHostGenerator, "_preprocess_data")
    @patch.object(disposableHostGenerator, "_postprocess_data")
    def test_scrape_retry_exhaustion(self, mock_post, mock_pre, mock_fetch, mock_sleep):
        """Test scrape gives up after max retries."""
        mock_fetch.return_value = b"data"
        mock_pre.return_value = ["domain1.com"]

        # Return 0 processed for first 4 calls (exhausts scrape_max_retry=3), then success
        mock_post.side_effect = [
            (0, 1),  # First: retry=1
            (0, 1),  # Second: retry=2
            (0, 1),  # Third: retry=3
            (0, 1),  # Fourth: retry=4 > scrape_max_retry=3, returns True
        ]

        gen = disposableHostGenerator()
        source = {"type": "html", "src": "https://example.com", "scrape": True, "timeout": 0.001}
        result = gen.process(source)

        # Returns True when retry limit exceeded (scrape gives up)
        assert result is True
        assert mock_post.call_count == 4


class TestFallbackDomainExtraction:
    """Tests for DOMAIN_SEARCH_RE fallback in _postprocess_data."""

    def test_fallback_extraction_no_valid_domains(self):
        """Test fallback extraction when no valid domains found."""
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        # Raw data contains domains but not in a clean format
        data = b'<html>contact us at "example.com" or "test.org"</html>'
        lines = []  # No valid lines after initial processing

        result = gen._postprocess_data(source, data, lines)

        # Should extract domains from raw data using DOMAIN_SEARCH_RE
        assert result is not False
        assert "example.com" in gen.domains
        assert "test.org" in gen.domains

    def test_fallback_extraction_also_empty(self):
        """Test when both initial and fallback extraction return empty."""
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        data = b"<html>No valid domains here at all</html>"
        lines = []

        result = gen._postprocess_data(source, data, lines)

        assert result is False
