"""Basic unit tests for the generator module.

Tests cover:
- Generator initialization and options
- Domain validation (check_valid_domains)
- DNS options retrieval
"""

from pathlib import Path
from unittest.mock import patch

from disposablehosts.generator import disposableHostGenerator


class TestGeneratorBasic:
    """Basic tests for disposableHostGenerator initialization."""

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


class TestGeneratorOptions:
    """Tests for various generator initialization options."""

    def test_init_with_verbose(self):
        """Test verbose option."""
        gen = disposableHostGenerator({"verbose": True})
        assert gen.options.get("verbose") is True

    def test_init_with_debug(self):
        """Test debug option."""
        gen = disposableHostGenerator({"debug": True})
        assert gen.options.get("debug") is True

    def test_init_with_source_map(self):
        """Test source_map option."""
        gen = disposableHostGenerator({"source_map": True})
        assert gen.options.get("source_map") is True

    def test_init_with_whitelist(self):
        """Test custom whitelist."""
        gen = disposableHostGenerator({"whitelist": "custom.txt"})
        wl = next((s for s in gen.sources if s.get("type") == "whitelist_file"), None)
        assert wl is not None
        assert wl["src"] == "custom.txt"

    def test_init_with_greylist(self):
        """Test custom greylist."""
        gen = disposableHostGenerator({"greylist": "custom.txt"})
        gl = next((s for s in gen.sources if s.get("type") == "greylist_file"), None)
        assert gl is not None
        assert gl["src"] == "custom.txt"

    def test_init_with_file(self):
        """Test custom file."""
        gen = disposableHostGenerator({"file": "custom.txt"})
        f = next((s for s in gen.sources if s.get("type") == "file"), None)
        assert f is not None
        assert f["src"] == "custom.txt"

    def test_init_skip_scrape(self):
        """Test skip_scrape option."""
        gen = disposableHostGenerator({"skip_scrape": True})
        assert gen.options.get("skip_scrape") is True

    def test_init_strict(self):
        """Test strict option."""
        gen = disposableHostGenerator({"strict": True})
        assert gen.options.get("strict") is True

    def test_init_dedicated_strict(self):
        """Test dedicated_strict option."""
        gen = disposableHostGenerator({"dedicated_strict": True})
        assert gen.options.get("dedicated_strict") is True

    def test_init_list_no_mx(self):
        """Test list_no_mx option."""
        gen = disposableHostGenerator({"list_no_mx": True})
        assert gen.options.get("list_no_mx") is True


class TestCheckValidDomains:
    """Tests for domain validation."""

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


class TestCheckValidDomainsExtended:
    """Extended tests for check_valid_domains edge cases."""

    def test_check_valid_domains_invalid_inputs(self):
        """Test validation with invalid domain inputs."""
        gen = disposableHostGenerator()
        # Various invalid inputs should return False
        assert gen.check_valid_domains(".") is False
        assert gen.check_valid_domains("..") is False
        assert gen.check_valid_domains("-") is False

    def test_check_valid_domains_empty_string(self):
        """Test validation with empty string."""
        gen = disposableHostGenerator()
        assert gen.check_valid_domains("") is False


class TestDomainValidationEdgeCases:
    """Tests for check_valid_domains edge cases."""

    def test_valid_domain_with_unicode(self):
        """Test validation with unicode domain (punycode)."""
        gen = disposableHostGenerator()
        # Punycode representation should work
        assert gen.check_valid_domains("xn--example-9q9a.com") is True

    def test_invalid_domain_format(self):
        """Test various invalid domain formats."""
        gen = disposableHostGenerator()
        assert gen.check_valid_domains(".invalid.com") is False
        assert gen.check_valid_domains("not_a_domain") is False


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


class TestGetDNSOptionsExtended:
    """Extended tests for _get_dns_options method with type coercion."""

    def test_dns_options_invalid_nameservers_type(self):
        """Test that non-list nameservers returns None."""
        gen = disposableHostGenerator({"nameservers": "not_a_list"})
        nameservers, dnsport, timeout = gen._get_dns_options()
        assert nameservers is None

    def test_dns_options_invalid_dnsport_type(self):
        """Test that non-int dnsport returns None."""
        gen = disposableHostGenerator({"dnsport": "not_an_int"})
        nameservers, dnsport, timeout = gen._get_dns_options()
        assert dnsport is None

    def test_dns_options_invalid_timeout_type(self):
        """Test that invalid timeout type defaults to 20."""
        gen = disposableHostGenerator({"dns_timeout": "not_a_number"})
        nameservers, dnsport, timeout = gen._get_dns_options()
        assert timeout == 20

    def test_dns_options_bool_timeout(self):
        """Test that bool timeout defaults to 20."""
        gen = disposableHostGenerator({"dns_timeout": True})
        nameservers, dnsport, timeout = gen._get_dns_options()
        assert timeout == 20


class TestInitOptionsExtended:
    """Extended tests for __init__ option handling."""

    def test_init_skip_src_not_list(self):
        """Test that non-list skip_src option is converted to list."""
        gen = disposableHostGenerator({"skip_src": "single_item"})
        assert gen.options.get("skip_src") == []

    def test_init_with_none_options(self):
        """Test initialization with None options."""
        gen = disposableHostGenerator(None)
        assert gen.options.get("skip_src") == []


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
