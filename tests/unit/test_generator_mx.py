"""MX verification and whitelist tests for the generator module.

Tests cover:
- MX record verification (_verify_mx_records)
- Whitelist application (_apply_whitelist)
- Greylist handling (add_greylist)
- DNS verification features
"""

import hashlib
from unittest.mock import patch

from disposablehosts.generator import disposableHostGenerator


class TestVerifyMXRecords:
    """Tests for _verify_mx_records method."""

    @patch("disposablehosts.generator.fetch_MX")
    def test_verify_mx_disabled(self, mock_fetch):
        """Test verify when disabled."""
        gen = disposableHostGenerator({"dns_verify": False})
        gen.domains = {"example.com"}
        gen._verify_mx_records()
        assert gen.no_mx == []
        mock_fetch.assert_not_called()

    @patch("disposablehosts.generator.fetch_MX")
    def test_verify_mx_empty_domains(self, mock_fetch):
        """Test verify with empty domains."""
        gen = disposableHostGenerator({"dns_verify": True})
        gen.domains = set()
        gen._verify_mx_records()
        assert gen.no_mx == []


class TestVerifyMXRecordsExtended:
    """Extended tests for _verify_mx_records with thread pools."""

    @patch("disposablehosts.generator.fetch_MX")
    def test_verify_multiple_domains_mixed_results(self, mock_fetch_mx):
        """Test MX verification with mixed valid/invalid domains."""

        def side_effect(domain, *args, **kwargs):
            # First and third domain valid, second invalid
            if domain in ["example.com", "test.org"]:
                return (domain, True)
            return (domain, False)

        mock_fetch_mx.side_effect = side_effect

        gen = disposableHostGenerator({"dns_verify": True})
        gen.domains = {"example.com", "invalid.com", "test.org"}
        gen._verify_mx_records()

        assert "invalid.com" in gen.no_mx
        assert "example.com" not in gen.no_mx
        assert "test.org" not in gen.no_mx

    @patch("disposablehosts.generator.fetch_MX")
    def test_verify_custom_thread_count(self, mock_fetch_mx):
        """Test MX verification with custom thread count."""
        mock_fetch_mx.return_value = ("example.com", True)

        gen = disposableHostGenerator({"dns_verify": True, "dns_threads": 4})
        gen.domains = {"example.com", "test.org"}
        gen._verify_mx_records()

        assert mock_fetch_mx.call_count == 2

    @patch("disposablehosts.generator.fetch_MX")
    def test_verify_invalid_thread_type(self, mock_fetch_mx):
        """Test MX verification with invalid dns_threads type defaults to 1."""
        mock_fetch_mx.return_value = ("example.com", True)

        gen = disposableHostGenerator({"dns_verify": True, "dns_threads": "invalid"})
        gen.domains = {"example.com"}
        gen._verify_mx_records()

        # Should still work even with invalid thread count
        assert mock_fetch_mx.called


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


class TestApplyWhitelistExtended:
    """Extended tests for _apply_whitelist with various options."""

    def test_apply_whitelist_non_strict_includes_grey(self):
        """Test non-strict mode includes greylist in skip set."""
        gen = disposableHostGenerator({"strict": False})
        gen.domains = {"example.com", "grey.com"}
        gen.skip = {"example.com"}
        gen.grey = {"grey.com"}

        gen._apply_whitelist()

        assert "example.com" not in gen.domains
        assert "grey.com" not in gen.domains

    def test_apply_whitelist_strict_excludes_grey(self):
        """Test strict mode excludes greylist from skip set."""
        gen = disposableHostGenerator({"strict": True})
        gen.domains = {"example.com", "grey.com"}
        gen.skip = {"example.com"}
        gen.grey = {"grey.com"}

        gen._apply_whitelist()

        assert "example.com" not in gen.domains
        assert "grey.com" in gen.domains  # Greylist kept when strict

    def test_apply_whitelist_removes_sha1(self):
        """Test that whitelisted domains have their SHA1 removed."""
        gen = disposableHostGenerator()
        gen.domains = {"example.com"}
        gen.skip = {"example.com"}
        gen.grey = set()

        # Add SHA1 hash for the domain
        sha1_hash = hashlib.sha1("example.com".encode("idna")).hexdigest()
        gen.sha1 = {sha1_hash}

        gen._apply_whitelist()

        assert sha1_hash not in gen.sha1


class TestApplyWhitelistDNSVerify:
    """Extended tests for _apply_whitelist with DNS verification."""

    @patch("disposablehosts.generator.fetch_MX")
    @patch("disposablehosts.generator.logging")
    def test_apply_whitelist_dns_verify_valid_mx(self, mock_logging, mock_fetch_mx):
        """Test whitelist with DNS verification when domain has valid MX."""
        mock_fetch_mx.return_value = ("whitelisted.com", True)

        gen = disposableHostGenerator({"dns_verify": True, "strict": True})
        gen.domains = {"example.com", "whitelisted.com"}
        gen.skip = {"whitelisted.com"}
        gen.grey = set()

        gen._apply_whitelist()

        assert "whitelisted.com" not in gen.domains
        mock_fetch_mx.assert_called_once()

    @patch("disposablehosts.generator.fetch_MX")
    @patch("disposablehosts.generator.logging")
    def test_apply_whitelist_dns_verify_no_mx(self, mock_logging, mock_fetch_mx):
        """Test whitelist with DNS verification when skipped domain has no MX."""
        mock_fetch_mx.return_value = ("whitelisted.com", False)

        gen = disposableHostGenerator({"dns_verify": True})
        gen.domains = {"example.com", "whitelisted.com"}
        gen.skip = {"whitelisted.com"}
        gen.grey = set()

        gen._apply_whitelist()

        # Should log warning when skipped domain has no MX
        mock_logging.warning.assert_called()

    @patch("disposablehosts.generator.fetch_MX")
    def test_apply_whitelist_skip_example_domains(self, mock_fetch_mx):
        """Test that example.com/org/net are skipped from DNS verification."""
        gen = disposableHostGenerator({"dns_verify": True})
        gen.domains = {"example.com", "example.org", "example.net", "other.com"}
        gen.skip = {"example.com", "example.org", "example.net", "other.com"}
        gen.grey = set()

        gen._apply_whitelist()

        # example domains should not trigger fetch_MX calls
        # only other.com should be checked
        assert mock_fetch_mx.call_count == 1
        mock_fetch_mx.assert_called_with("other.com", None, None, 20)


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


class TestGreylistErrorHandling:
    """Tests for add_greylist error handling."""

    def test_add_greylist_sha1_encoding_error(self):
        """Test that SHA1 encoding errors are handled gracefully."""
        gen = disposableHostGenerator()
        gen.domains = set()
        # Domain that might cause encoding issues
        gen.grey = {"\ud800invalid.com"}  # Surrogate character

        # Should not raise exception
        gen.add_greylist()
        # Domain should still be added to domains
        assert len(gen.domains) == 1
