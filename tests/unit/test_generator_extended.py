"""Extended unit tests for the generator module."""

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from disposablehosts.generator import disposableHostGenerator


class TestDisposableHostGeneratorInit:
    """Tests for generator initialization."""

    def test_init_with_empty_options(self):
        """Test initialization with empty options."""
        gen = disposableHostGenerator()
        assert gen.options == {"skip_src": []}
        assert gen.out_file == "domains"
        assert gen.domains == set()
        assert gen.sha1 == set()

    def test_init_skip_src_not_list(self):
        """Test that skip_src is converted to list if not already."""
        gen = disposableHostGenerator({"skip_src": "not_a_list"})
        assert gen.options["skip_src"] == []

    def test_init_verbose_logging(self):
        """Test verbose logging setup."""
        gen = disposableHostGenerator({"verbose": True})
        assert gen.options.get("verbose") is True

    def test_init_debug_logging(self):
        """Test debug logging setup."""
        gen = disposableHostGenerator({"debug": True})
        assert gen.options.get("debug") is True

    def test_init_with_custom_file(self):
        """Test initialization with custom file option."""
        gen = disposableHostGenerator({"file": "custom.txt"})
        first_source = gen.sources[0]
        assert first_source["type"] == "file"
        assert first_source["src"] == "custom.txt"

    def test_init_with_custom_whitelist(self):
        """Test initialization with custom whitelist."""
        gen = disposableHostGenerator({"whitelist": "custom_whitelist.txt"})
        whitelist_source = next(s for s in gen.sources if s.get("type") == "whitelist_file")
        assert whitelist_source["src"] == "custom_whitelist.txt"

    def test_init_with_custom_greylist(self):
        """Test initialization with custom greylist."""
        gen = disposableHostGenerator({"greylist": "custom_greylist.txt"})
        greylist_source = next(s for s in gen.sources if s.get("type") == "greylist_file")
        assert greylist_source["src"] == "custom_greylist.txt"


class TestFetchData:
    """Tests for _fetch_data method."""

    @patch("disposablehosts.generator.fetch_file_source")
    def test_fetch_data_file_type(self, mock_fetch_file):
        """Test fetching file type source."""
        mock_fetch_file.return_value = b"example.com\n"
        gen = disposableHostGenerator()
        source = {"type": "file", "src": "test.txt", "ignore_not_exists": False}
        result = gen._fetch_data(source)
        assert result == b"example.com\n"
        mock_fetch_file.assert_called_with("test.txt", False)

    @patch("disposablehosts.generator.fetch_file_source")
    def test_fetch_data_whitelist_file_type(self, mock_fetch_file):
        """Test fetching whitelist_file type source."""
        mock_fetch_file.return_value = b"example.com\n"
        gen = disposableHostGenerator()
        source = {"type": "whitelist_file", "src": "whitelist.txt", "ignore_not_exists": True}
        result = gen._fetch_data(source)
        assert result == b"example.com\n"

    @patch("disposablehosts.generator.fetch_file_source")
    def test_fetch_data_greylist_file_type(self, mock_fetch_file):
        """Test fetching greylist_file type source."""
        mock_fetch_file.return_value = b"example.com\n"
        gen = disposableHostGenerator()
        source = {"type": "greylist_file", "src": "greylist.txt", "ignore_not_exists": True}
        result = gen._fetch_data(source)
        assert result == b"example.com\n"

    @patch("disposablehosts.generator.fetch_websocket_source")
    def test_fetch_data_websocket_type(self, mock_fetch_ws):
        """Test fetching ws type source."""
        mock_fetch_ws.return_value = b"domain1.com,domain2.com"
        gen = disposableHostGenerator()
        source = {"type": "ws", "src": "wss://example.com/ws"}
        result = gen._fetch_data(source)
        assert result == b"domain1.com,domain2.com"

    @patch("disposablehosts.generator.fetch_http_source")
    def test_fetch_data_http_json_type(self, mock_fetch_http):
        """Test fetching json type source with custom headers."""
        mock_fetch_http.return_value = b'["example.com"]'
        gen = disposableHostGenerator({"max_retry": 5})
        source = {"type": "json", "src": "https://api.example.com/domains", "timeout": 10}
        result = gen._fetch_data(source)
        assert result == b'["example.com"]'
        mock_fetch_http.assert_called_once()
        call_args = mock_fetch_http.call_args
        assert call_args[0][0] == "https://api.example.com/domains"
        assert call_args[0][1]["Accept"] == "application/json, text/javascript, */*; q=0.01"
        assert call_args[0][1]["X-Requested-With"] == "XMLHttpRequest"
        assert call_args[0][2] == 10
        assert call_args[1]["max_retry"] == 5

    @patch("disposablehosts.generator.fetch_http_source")
    def test_fetch_data_http_html_type(self, mock_fetch_http):
        """Test fetching html type source."""
        mock_fetch_http.return_value = b"<html><option>@example.com</option></html>"
        gen = disposableHostGenerator()
        source = {"type": "html", "src": "https://example.com"}
        result = gen._fetch_data(source)
        assert result == b"<html><option>@example.com</option></html>"


class TestPreprocessData:
    """Tests for _preprocess_data method."""

    def test_preprocess_data_returns_list_as_is(self):
        """Test that list data is returned as-is."""
        gen = disposableHostGenerator()
        source = {"type": "json"}
        result = gen._preprocess_data(source, ["domain1.com", "domain2.com"])
        assert result == ["domain1.com", "domain2.com"]

    def test_preprocess_data_sha1(self):
        """Test SHA1 preprocessing adds to sha1 set."""
        gen = disposableHostGenerator()
        gen.sha1 = set()
        source = {"type": "sha1"}
        data = b"a" * 40 + b"\n" + b"b" * 40 + b"\n"
        result = gen._preprocess_data(source, data)
        assert result == []
        assert len(gen.sha1) == 2

    def test_preprocess_data_websocket(self):
        """Test WebSocket preprocessing."""
        gen = disposableHostGenerator()
        source = {"type": "ws"}
        data = b"Ddomain1.com,domain2.com"
        result = gen._preprocess_data(source, data)
        assert result == ["domain1.com", "domain2.com"]

    def test_preprocess_data_html_with_regex(self):
        """Test HTML preprocessing with regex."""
        from disposablehosts.constants import HTML_GENERIC_RE

        gen = disposableHostGenerator()
        source = {"type": "html", "regex": HTML_GENERIC_RE, "encoding": "utf-8"}
        data = b"<option>@example.com (PW)</option><option>test.org</option>"
        result = gen._preprocess_data(source, data)
        assert "example.com" in result
        assert "test.org" in result

    def test_preprocess_data_json(self):
        """Test JSON preprocessing."""
        gen = disposableHostGenerator()
        source = {"type": "json", "encoding": "utf-8"}
        data = b'["example.com", "test.org"]'
        result = gen._preprocess_data(source, data)
        assert result == ["example.com", "test.org"]

    def test_preprocess_data_file_types(self):
        """Test file type preprocessing (list, file, whitelist, etc.)."""
        gen = disposableHostGenerator()
        for fmt in ["whitelist", "list", "file", "whitelist_file", "greylist", "greylist_file"]:
            source = {"type": fmt, "encoding": "utf-8"}
            data = b"# Comment\nexample.com\n\ntest.org\n"
            result = gen._preprocess_data(source, data)
            assert result == ["example.com", "test.org"], f"Failed for format: {fmt}"

    def test_preprocess_data_unknown_type(self):
        """Test unknown type returns None."""
        gen = disposableHostGenerator()
        source = {"type": "unknown"}
        result = gen._preprocess_data(source, b"data")
        assert result is None


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

    def test_postprocess_no_results(self):
        """Test postprocessing with no valid results."""
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        data = b"invalid_data"
        lines = ["not_a_valid_domain"]
        result = gen._postprocess_data(source, data, lines)
        assert result is False

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
        assert "test.org" in gen.scrape

    def test_postprocess_sha1_whitelist(self):
        """Test postprocessing sha1 whitelist source."""
        gen = disposableHostGenerator()
        source = {"type": "sha1", "src": "https://example.com"}
        data = b"hash1\nhash2"
        lines = ["hash1", "hash2"]
        result = gen._postprocess_data(source, data, lines)
        assert result is True
        assert "hash1" in gen.skip
        assert "hash2" in gen.skip

    def test_postprocess_domain_fallback_search(self):
        """Test fallback domain search when no valid domains in lines."""
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        data = b'<html>"example.com"</html>'
        lines = ["not_a_domain"]
        result = gen._postprocess_data(source, data, lines)
        # Should find example.com via DOMAIN_SEARCH_RE
        assert "example.com" in gen.domains


class TestProcessSource:
    """Tests for process method."""

    @patch.object(disposableHostGenerator, "_fetch_data")
    @patch.object(disposableHostGenerator, "_preprocess_data")
    @patch.object(disposableHostGenerator, "_postprocess_data")
    def test_process_success(self, mock_postprocess, mock_preprocess, mock_fetch):
        """Test successful processing."""
        mock_fetch.return_value = b"data"
        mock_preprocess.return_value = ["example.com"]
        mock_postprocess.return_value = (1, 1)

        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        result = gen.process(source)
        assert result is True

    @patch.object(disposableHostGenerator, "_fetch_data")
    def test_process_fetch_returns_none(self, mock_fetch):
        """Test processing when fetch returns None."""
        mock_fetch.return_value = None
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        result = gen.process(source)
        assert result is False

    @patch.object(disposableHostGenerator, "_fetch_data")
    @patch.object(disposableHostGenerator, "_preprocess_data")
    def test_process_preprocess_returns_none(self, mock_preprocess, mock_fetch):
        """Test processing when preprocess returns None."""
        mock_fetch.return_value = b"data"
        mock_preprocess.return_value = None
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        result = gen.process(source)
        assert result is False

    @patch.object(disposableHostGenerator, "_fetch_data")
    @patch.object(disposableHostGenerator, "_preprocess_data")
    @patch.object(disposableHostGenerator, "_postprocess_data")
    def test_process_skip_scrape(self, mock_postprocess, mock_preprocess, mock_fetch):
        """Test skip_scrape option disables scraping."""
        mock_fetch.return_value = b"data"
        mock_preprocess.return_value = ["example.com"]
        mock_postprocess.return_value = (1, 1)

        gen = disposableHostGenerator({"skip_scrape": True})
        source = {"type": "html", "src": "https://example.com", "scrape": True}
        gen.process(source)
        assert source.get("scrape") is False

    @patch.object(disposableHostGenerator, "_fetch_data")
    @patch.object(disposableHostGenerator, "_preprocess_data")
    @patch.object(disposableHostGenerator, "_postprocess_data")
    @patch("disposablehosts.generator.time.sleep")
    def test_process_scrape_with_retry(self, mock_sleep, mock_postprocess, mock_preprocess, mock_fetch):
        """Test scrape mode with retry logic."""
        mock_fetch.return_value = b"data"
        mock_preprocess.return_value = ["example.com"]
        # First call returns 0 processed, second returns 1
        mock_postprocess.side_effect = [(0, 1), (1, 1)]

        gen = disposableHostGenerator()
        source = {"type": "html", "src": "https://example.com", "scrape": True, "timeout": 1}
        result = gen.process(source)
        assert result is True
        mock_sleep.assert_called_once_with(1)


class TestProcessTempmailo:
    """Tests for _processTempmailo method."""

    @patch("disposablehosts.generator.fetch_http_source_raw")
    @patch("disposablehosts.generator.fetch_http_source")
    def test_process_tempmailo_success(self, mock_fetch_http, mock_fetch_raw):
        """Test successful tempmailo processing."""
        mock_response = MagicMock()
        mock_response.headers = {"set-cookie": "session=abc123; path=/"}
        mock_response.read.return_value = b'<input name="__RequestVerificationToken" value="token123" />'
        mock_fetch_raw.return_value = mock_response
        mock_fetch_http.return_value = b"user@domain1.com\nuser@domain2.com"

        gen = disposableHostGenerator()
        result = gen._processTempmailo()
        assert result == ["domain1.com", "domain2.com"]

    @patch("disposablehosts.generator.fetch_http_source_raw")
    def test_process_tempmailo_no_response(self, mock_fetch_raw):
        """Test tempmailo when fetch returns None."""
        mock_fetch_raw.return_value = None
        gen = disposableHostGenerator()
        result = gen._processTempmailo()
        assert result is None

    @patch("disposablehosts.generator.fetch_http_source_raw")
    @patch("disposablehosts.generator.fetch_http_source")
    def test_process_tempmailo_no_token(self, mock_fetch_http, mock_fetch_raw):
        """Test tempmailo when token not found."""
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.read.return_value = b"<html>No token here</html>"
        mock_fetch_raw.return_value = mock_fetch_raw
        mock_fetch_raw.return_value = mock_response

        gen = disposableHostGenerator()
        result = gen._processTempmailo()
        assert result is None


class TestReadFiles:
    """Tests for read_files method."""

    def test_read_files_success(self, tmp_path: Path):
        """Test reading existing files."""
        gen = disposableHostGenerator()
        gen.out_file = str(tmp_path / "domains")

        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("example.com\ntest.org")

        sha1_file = tmp_path / "domains_sha1.txt"
        sha1_file.write_text("hash1\nhash2")

        legacy_file = tmp_path / "domains_legacy.txt"
        legacy_file.write_text("legacy1.com\nlegacy2.com")

        gen.read_files()
        assert "example.com" in gen.old_domains
        assert "test.org" in gen.old_domains
        assert "hash1" in gen.old_sha1
        assert "legacy1.com" in gen.legacy_domains

    def test_read_files_missing(self, tmp_path: Path):
        """Test reading when files don't exist."""
        gen = disposableHostGenerator()
        gen.out_file = str(tmp_path / "nonexistent")
        gen.read_files()
        assert gen.old_domains == set()
        assert gen.old_sha1 == set()
        assert gen.legacy_domains == set()


class TestListSources:
    """Tests for list_sources method."""

    @patch("disposablehosts.generator.logging.info")
    def test_list_sources(self, mock_info):
        """Test listing sources."""
        gen = disposableHostGenerator()
        gen.list_sources()
        assert mock_info.called


class TestAddGreylist:
    """Tests for add_greylist method."""

    def test_add_greylist(self):
        """Test adding greylist to domains."""
        gen = disposableHostGenerator()
        gen.domains = {"example.com"}
        gen.grey = {"grey1.com", "grey2.com"}
        gen.add_greylist()
        assert "grey1.com" in gen.domains
        assert "grey2.com" in gen.domains
        assert "grey1.com" in gen.source_map["greylist"]


class TestShouldSkipSource:
    """Tests for _should_skip_source method."""

    def test_should_skip_by_src_filter(self):
        """Test skipping by src_filter."""
        gen = disposableHostGenerator({"src_filter": "specific_source"})
        source = {"src": "other_source"}
        assert gen._should_skip_source(source) is True

    def test_should_not_skip_whitelist_by_filter(self):
        """Test that whitelist_file is not skipped by src_filter."""
        gen = disposableHostGenerator({"src_filter": "some_filter"})
        source = {"src": "whitelist_file"}
        assert gen._should_skip_source(source) is False

    def test_should_skip_by_skip_src(self):
        """Test skipping by skip_src list."""
        gen = disposableHostGenerator({"skip_src": ["skip_me"]})
        source = {"src": "skip_me"}
        assert gen._should_skip_source(source) is True

    def test_should_not_skip(self):
        """Test not skipping valid source."""
        gen = disposableHostGenerator()
        source = {"src": "valid_source"}
        assert gen._should_skip_source(source) is False


class TestGetDNSOptions:
    """Tests for _get_dns_options method."""

    def test_get_dns_options_defaults(self):
        """Test default DNS options."""
        gen = disposableHostGenerator()
        nameservers, dnsport, timeout = gen._get_dns_options()
        assert nameservers is None
        assert dnsport is None
        assert timeout == 20

    def test_get_dns_options_custom(self):
        """Test custom DNS options."""
        gen = disposableHostGenerator({
            "nameservers": ["8.8.8.8", "1.1.1.1"],
            "dnsport": 5353,
            "dns_timeout": 30.5,
        })
        nameservers, dnsport, timeout = gen._get_dns_options()
        assert nameservers == ["8.8.8.8", "1.1.1.1"]
        assert dnsport == 5353
        assert timeout == 30

    def test_get_dns_options_invalid_types(self):
        """Test handling of invalid types."""
        gen = disposableHostGenerator({
            "nameservers": "not_a_list",
            "dnsport": "not_an_int",
            "dns_timeout": True,
        })
        nameservers, dnsport, timeout = gen._get_dns_options()
        assert nameservers is None
        assert dnsport is None
        assert timeout == 20


class TestApplyWhitelist:
    """Tests for _apply_whitelist method."""

    @patch("disposablehosts.generator.fetch_MX")
    def test_apply_whitelist_basic(self, mock_fetch_mx):
        """Test basic whitelist application."""
        gen = disposableHostGenerator()
        gen.domains = {"example.com", "test.org"}
        gen.skip = {"example.com"}
        gen._apply_whitelist()
        assert "example.com" not in gen.domains
        assert "test.org" in gen.domains

    @patch("disposablehosts.generator.fetch_MX")
    def test_apply_whitelist_with_greylist(self, mock_fetch_mx):
        """Test whitelist with greylist in non-strict mode."""
        gen = disposableHostGenerator({"strict": False})
        gen.domains = {"example.com", "grey.com"}
        gen.skip = {"example.com"}
        gen.grey = {"grey.com"}
        gen._apply_whitelist()
        assert "grey.com" not in gen.domains

    @patch("disposablehosts.generator.fetch_MX")
    def test_apply_whitelist_with_dns_verify(self, mock_fetch_mx):
        """Test whitelist with DNS verification."""
        mock_fetch_mx.return_value = ("example.com", False)
        gen = disposableHostGenerator({"dns_verify": True})
        gen.domains = {"example.com"}
        gen.skip = {"example.com"}
        gen._apply_whitelist()
        mock_fetch_mx.assert_called_with("example.com", None, None, 20)


class TestVerifyMXRecords:
    """Tests for _verify_mx_records method."""

    @patch("disposablehosts.utils.dns.fetch_MX")
    def test_verify_mx_records(self, mock_fetch_mx):
        """Test MX verification."""
        mock_fetch_mx.return_value = ("example.com", True)
        gen = disposableHostGenerator({"dns_verify": True, "dns_threads": 2})
        gen.domains = {"example.com", "test.org"}
        gen._verify_mx_records()
        assert len(gen.no_mx) == 0

    @patch("disposablehosts.utils.dns.fetch_MX")
    def test_verify_mx_records_invalid(self, mock_fetch_mx):
        """Test MX verification with invalid domains."""
        mock_fetch_mx.return_value = ("example.com", False)
        gen = disposableHostGenerator({"dns_verify": True, "dns_threads": 2})
        gen.domains = {"example.com"}
        gen._verify_mx_records()
        assert "example.com" in gen.no_mx

    def test_verify_mx_records_disabled(self):
        """Test MX verification when disabled."""
        gen = disposableHostGenerator({"dns_verify": False})
        gen.domains = {"example.com"}
        gen._verify_mx_records()
        assert gen.no_mx == []


class TestLogGenerationResults:
    """Tests for _log_generation_results method."""

    @patch.object(disposableHostGenerator, "read_files")
    @patch("disposablehosts.generator.logging.info")
    def test_log_results_quiet(self, mock_info, mock_read):
        """Test logging when quiet mode."""
        gen = disposableHostGenerator({"verbose": False})
        result = gen._log_generation_results()
        assert result is True
        mock_info.assert_not_called()

    @patch.object(disposableHostGenerator, "read_files")
    @patch("disposablehosts.generator.logging.info")
    def test_log_results_no_changes(self, mock_info, mock_read):
        """Test logging when no changes detected."""
        gen = disposableHostGenerator({"verbose": True})
        gen.domains = {"example.com"}
        gen.old_domains = {"example.com"}
        gen.sha1 = {"hash1"}
        gen.old_sha1 = {"hash1"}
        result = gen._log_generation_results()
        assert result is False

    @patch.object(disposableHostGenerator, "read_files")
    @patch("disposablehosts.generator.logging.info")
    def test_log_results_with_changes(self, mock_info, mock_read):
        """Test logging when changes detected."""
        gen = disposableHostGenerator({"verbose": True})
        gen.domains = {"example.com", "new.com"}
        gen.old_domains = {"example.com"}
        gen.sha1 = {"hash1"}
        gen.old_sha1 = {"hash1"}
        result = gen._log_generation_results()
        assert result is True

    @patch.object(disposableHostGenerator, "read_files")
    @patch("disposablehosts.generator.logging.info")
    def test_log_results_with_dns_verify(self, mock_info, mock_read):
        """Test logging with DNS verification enabled."""
        gen = disposableHostGenerator({"verbose": True, "dns_verify": True, "list_no_mx": True})
        gen.domains = {"example.com"}
        gen.no_mx = ["example.com"]
        gen.old_domains = {"example.com"}
        gen.sha1 = {"hash1"}
        gen.old_sha1 = {"hash1"}
        gen._log_generation_results()
        mock_info.assert_any_call("No MX: %s", ["example.com"])

    @patch.object(disposableHostGenerator, "read_files")
    @patch("disposablehosts.generator.logging.info")
    def test_log_results_with_src_filter(self, mock_info, mock_read):
        """Test logging with src_filter."""
        gen = disposableHostGenerator({"verbose": True, "src_filter": "source1"})
        gen.domains = {"example.com"}
        gen.old_domains = set()
        gen.sha1 = set()
        gen.old_sha1 = set()
        gen._log_generation_results()
        mock_info.assert_any_call("Fetched: %s", {"example.com"})


class TestGenerate:
    """Tests for generate method."""

    @patch.object(disposableHostGenerator, "_fetch_sources")
    @patch.object(disposableHostGenerator, "_apply_whitelist")
    @patch.object(disposableHostGenerator, "_verify_mx_records")
    @patch.object(disposableHostGenerator, "_log_generation_results")
    def test_generate_success(self, mock_log, mock_verify, mock_apply, mock_fetch):
        """Test successful generation."""
        mock_log.return_value = True
        gen = disposableHostGenerator()
        result = gen.generate()
        assert result is True
        mock_fetch.assert_called_once()
        mock_apply.assert_called_once()
        mock_verify.assert_called_once()

    @patch.object(disposableHostGenerator, "_fetch_sources")
    @patch.object(disposableHostGenerator, "_apply_whitelist")
    @patch.object(disposableHostGenerator, "_verify_mx_records")
    @patch.object(disposableHostGenerator, "_log_generation_results")
    def test_generate_no_changes(self, mock_log, mock_verify, mock_apply, mock_fetch):
        """Test generation with no changes."""
        mock_log.return_value = False
        gen = disposableHostGenerator()
        result = gen.generate()
        assert result is False


class TestWriteToFile:
    """Tests for write_to_file method."""

    def test_write_to_file_basic(self, tmp_path: Path):
        """Test basic file writing."""
        gen = disposableHostGenerator()
        gen.out_file = str(tmp_path / "domains")
        gen.domains = {"example.com", "test.org"}
        gen.sha1 = {"hash1", "hash2"}

        gen.write_to_file()

        domains_txt = (tmp_path / "domains.txt").read_text()
        assert "example.com" in domains_txt
        assert "test.org" in domains_txt

        domains_json = json.loads((tmp_path / "domains.json").read_text())
        assert "example.com" in domains_json

        sha1_txt = (tmp_path / "domains_sha1.txt").read_text()
        assert "hash1" in sha1_txt

    def test_write_to_file_with_source_map(self, tmp_path: Path):
        """Test file writing with source map."""
        gen = disposableHostGenerator({"source_map": True})
        gen.out_file = str(tmp_path / "domains")
        gen.domains = {"example.com"}
        gen.source_map = {"https://example.com": ["example.com"]}
        gen.sha1 = {"hash1"}

        gen.write_to_file()

        source_map = (tmp_path / "domains_source_map.txt").read_text()
        assert "https://example.com" in source_map

    def test_write_to_file_with_no_mx(self, tmp_path: Path):
        """Test file writing with no_mx domains."""
        gen = disposableHostGenerator()
        gen.out_file = str(tmp_path / "domains")
        gen.domains = {"example.com", "no-mx.com"}
        gen.no_mx = ["no-mx.com"]
        gen.sha1 = {"hash1"}

        gen.write_to_file()

        # Main file should have all domains
        domains_txt = (tmp_path / "domains.txt").read_text()
        assert "no-mx.com" in domains_txt

        # MX file should exclude no-mx domains
        mx_txt = (tmp_path / "domains_mx.txt").read_text()
        assert "example.com" in mx_txt
        assert "no-mx.com" not in mx_txt
