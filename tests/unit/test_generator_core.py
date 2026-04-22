"""Core unit tests for the generator module."""

from pathlib import Path
from unittest.mock import patch


from disposablehosts.generator import disposableHostGenerator


class TestGeneratorBasic:
    """Basic tests for disposableHostGenerator."""

    def test_init_defaults(self):
        """Test initialization with default values."""
        gen = disposableHostGenerator()
        assert gen.out_file == "domains"
        assert gen.domains == set()
        assert gen.sha1 == set()
        assert gen.options.get("skip_src") == []

    def test_init_with_outfile(self):
        """Test initialization with custom output file."""
        gen = disposableHostGenerator({}, "custom_output")
        assert gen.out_file == "custom_output"

    def test_check_valid_domains_valid(self):
        """Test domain validation with valid domains."""
        gen = disposableHostGenerator()
        assert gen.check_valid_domains("example.com") is True
        assert gen.check_valid_domains("sub.example.com") is True
        assert gen.check_valid_domains("my-domain.org") is True

    def test_check_valid_domains_invalid(self):
        """Test domain validation with invalid domains."""
        gen = disposableHostGenerator()
        assert gen.check_valid_domains("not_a_domain") is False
        assert gen.check_valid_domains("") is False
        assert gen.check_valid_domains(".example.com") is False
        assert gen.check_valid_domains("invalid..") is False


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
            "nameservers": ["8.8.8.8"],
            "dnsport": 5353,
            "dns_timeout": 30,
        })
        nameservers, dnsport, timeout = gen._get_dns_options()
        assert nameservers == ["8.8.8.8"]
        assert dnsport == 5353
        assert timeout == 30


class TestApplyWhitelist:
    """Tests for _apply_whitelist method."""

    def test_apply_whitelist_basic(self):
        """Test basic whitelist application."""
        gen = disposableHostGenerator()
        gen.domains = {"example.com", "test.org"}
        gen.skip = {"example.com"}
        gen.grey = set()
        gen._apply_whitelist()
        assert "example.com" not in gen.domains
        assert "test.org" in gen.domains

    def test_apply_whitelist_with_greylist(self):
        """Test whitelist with greylist."""
        gen = disposableHostGenerator({"strict": False})
        gen.domains = {"example.com", "grey.com"}
        gen.skip = {"example.com"}
        gen.grey = {"grey.com"}
        gen._apply_whitelist()
        assert "grey.com" not in gen.domains


class TestReadFiles:
    """Tests for read_files method."""

    def test_read_files_success(self, tmp_path: Path):
        """Test reading existing files."""
        gen = disposableHostGenerator()
        gen.out_file = str(tmp_path / "domains")

        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("example.com\ntest.org")

        gen.read_files()
        assert "example.com" in gen.old_domains
        assert "test.org" in gen.old_domains

    def test_read_files_missing(self, tmp_path: Path):
        """Test reading when files don't exist."""
        gen = disposableHostGenerator()
        gen.out_file = str(tmp_path / "nonexistent")
        gen.read_files()
        assert gen.old_domains == set()


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


class TestWriteToFile:
    """Tests for write_to_file method."""

    def test_write_to_file_basic(self, tmp_path: Path):
        """Test basic file writing."""
        gen = disposableHostGenerator()
        gen.out_file = str(tmp_path / "domains")
        gen.domains = {"example.com", "test.org"}
        gen.sha1 = {"hash1"}

        gen.write_to_file()

        domains_txt = (tmp_path / "domains.txt").read_text()
        assert "example.com" in domains_txt
        assert "test.org" in domains_txt

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
