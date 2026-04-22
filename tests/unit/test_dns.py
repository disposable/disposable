"""Unit tests for the DNS utilities module."""

from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver

from disposablehosts.utils.dns import (
    _process_mx_resolution,
    _validate_ip_addresses,
    fetch_MX,
    resolve_DNS_cached,
)


class TestResolveDNSCached:
    """Tests for resolve_DNS_cached function."""

    @patch("disposablehosts.utils.dns.dns.resolver.Resolver")
    def test_resolve_success(self, mock_resolver_class):
        """Test successful DNS resolution."""
        mock_resolver = MagicMock()
        mock_answer = MagicMock()
        mock_resolver.resolve.return_value = mock_answer
        mock_resolver_class.return_value = mock_resolver

        result = resolve_DNS_cached("example.com", dns.rdatatype.A)
        assert result == mock_answer

    @patch("disposablehosts.utils.dns.dns.resolver.Resolver")
    def test_resolve_with_nameservers(self, mock_resolver_class):
        """Test DNS resolution with custom nameservers."""
        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = MagicMock()
        mock_resolver_class.return_value = mock_resolver

        result = resolve_DNS_cached("example.com", dns.rdatatype.A, (["8.8.8.8"], 53, 10))
        assert mock_resolver.nameservers == ["8.8.8.8"]
        assert mock_resolver.port == 53
        assert mock_resolver.lifetime == 10

    @patch("disposablehosts.utils.dns.dns.resolver.Resolver")
    def test_resolve_nxdomain(self, mock_resolver_class):
        """Test DNS resolution with NXDOMAIN."""
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN
        mock_resolver_class.return_value = mock_resolver

        result = resolve_DNS_cached("example.com", dns.rdatatype.A)
        assert result == "resolved but no entry"

    @patch("disposablehosts.utils.dns.dns.resolver.Resolver")
    def test_resolve_no_nameservers(self, mock_resolver_class):
        """Test DNS resolution with NoNameservers."""
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NoNameservers
        mock_resolver_class.return_value = mock_resolver

        result = resolve_DNS_cached("example.com", dns.rdatatype.A)
        assert result == "answer refused"

    @patch("disposablehosts.utils.dns.dns.resolver.Resolver")
    def test_resolve_no_answer(self, mock_resolver_class):
        """Test DNS resolution with NoAnswer."""
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer
        mock_resolver_class.return_value = mock_resolver

        result = resolve_DNS_cached("example.com", dns.rdatatype.A)
        assert result == "no answer section"

    @patch("disposablehosts.utils.dns.dns.resolver.Resolver")
    def test_resolve_timeout(self, mock_resolver_class):
        """Test DNS resolution with Timeout."""
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.exception.Timeout
        mock_resolver_class.return_value = mock_resolver

        result = resolve_DNS_cached("example.com", dns.rdatatype.A)
        assert result == "timeout"

    @patch("disposablehosts.utils.dns.dns.resolver.Resolver")
    def test_resolve_keyboard_interrupt(self, mock_resolver_class):
        """Test DNS resolution with KeyboardInterrupt."""
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = KeyboardInterrupt
        mock_resolver_class.return_value = mock_resolver

        with pytest.raises(KeyboardInterrupt):
            resolve_DNS_cached("example.com", dns.rdatatype.A)

    @patch("disposablehosts.utils.dns.dns.resolver.Resolver")
    def test_resolve_generic_exception(self, mock_resolver_class):
        """Test DNS resolution with generic exception."""
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("Some error")
        mock_resolver_class.return_value = mock_resolver

        result = resolve_DNS_cached("example.com", dns.rdatatype.A)
        assert result is None


class TestProcessMXResolution:
    """Tests for _process_mx_resolution function."""

    @patch("disposablehosts.utils.dns.resolve_DNS_cached")
    def test_process_mx_success(self, mock_resolve):
        """Test successful MX processing."""
        mock_answer = MagicMock()
        mock_rr = MagicMock()
        mock_rr.exchange.to_text.return_value = "mail.example.com"
        mock_answer.rrset = [mock_rr]
        mock_resolve.return_value = mock_answer

        result = _process_mx_resolution("example.com", ("example.com", dns.rdatatype.MX, "MX"), (None, None, 20))
        assert result == ({"mail.example.com"}, False)

    @patch("disposablehosts.utils.dns.resolve_DNS_cached")
    def test_process_mx_string_result(self, mock_resolve):
        """Test MX processing when resolve returns string (error)."""
        mock_resolve.return_value = "resolved but no entry"

        result = _process_mx_resolution("example.com", ("example.com", dns.rdatatype.MX, "MX"), (None, None, 20))
        assert result == (None, False)

    @patch("disposablehosts.utils.dns.resolve_DNS_cached")
    def test_process_mx_non_mx_type(self, mock_resolve):
        """Test MX processing with non-MX record type."""
        mock_answer = MagicMock()
        mock_resolve.return_value = mock_answer

        result = _process_mx_resolution("example.com", ("example.com", dns.rdatatype.A, "A"), (None, None, 20))
        assert result == (None, False)

    @patch("disposablehosts.utils.dns.resolve_DNS_cached")
    def test_process_mx_empty_list(self, mock_resolve):
        """Test MX processing with empty MX list."""
        mock_answer = MagicMock()
        mock_answer.rrset = []
        mock_resolve.return_value = mock_answer

        result = _process_mx_resolution("example.com", ("example.com", dns.rdatatype.MX, "MX"), (None, None, 20))
        assert result == (set(), False)

    @patch("disposablehosts.utils.dns.resolve_DNS_cached")
    def test_process_mx_invalid_mx(self, mock_resolve):
        """Test MX processing with invalid MX (localhost or dot)."""
        mock_answer = MagicMock()
        mock_rr = MagicMock()
        mock_rr.exchange.to_text.return_value = "."
        mock_answer.rrset = [mock_rr]
        mock_resolve.return_value = mock_answer

        result = _process_mx_resolution("example.com", ("example.com", dns.rdatatype.MX, "MX"), (None, None, 20))
        assert result == ({"."}, True)

    @patch("disposablehosts.utils.dns.resolve_DNS_cached")
    def test_process_mx_localhost(self, mock_resolve):
        """Test MX processing with localhost MX."""
        mock_answer = MagicMock()
        mock_rr = MagicMock()
        mock_rr.exchange.to_text.return_value = "localhost"
        mock_answer.rrset = [mock_rr]
        mock_resolve.return_value = mock_answer

        result = _process_mx_resolution("example.com", ("example.com", dns.rdatatype.MX, "MX"), (None, None, 20))
        assert result == ({"localhost"}, True)


class TestValidateIPAddresses:
    """Tests for _validate_ip_addresses function."""

    def test_validate_valid_public_ip(self):
        """Test validation of valid public IP."""
        mock_r = [MagicMock()]
        mock_r[0].address = "8.8.8.8"

        invalid, ips = _validate_ip_addresses(mock_r)
        assert invalid is False
        assert ips == ["8.8.8.8"]

    def test_validate_private_ip(self):
        """Test validation of private IP."""
        mock_r = [MagicMock()]
        mock_r[0].address = "192.168.1.1"

        invalid, ips = _validate_ip_addresses(mock_r)
        assert invalid is True
        assert ips == ["192.168.1.1"]

    def test_validate_loopback_ip(self):
        """Test validation of loopback IP."""
        mock_r = [MagicMock()]
        mock_r[0].address = "127.0.0.1"

        invalid, ips = _validate_ip_addresses(mock_r)
        assert invalid is True

    def test_validate_reserved_ip(self):
        """Test validation of reserved IP."""
        mock_r = [MagicMock()]
        # 240.0.0.0/4 is reserved
        mock_r[0].address = "240.0.0.1"

        invalid, ips = _validate_ip_addresses(mock_r)
        assert invalid is True

    def test_validate_multicast_ip(self):
        """Test validation of multicast IP."""
        mock_r = [MagicMock()]
        mock_r[0].address = "224.0.0.1"

        invalid, ips = _validate_ip_addresses(mock_r)
        assert invalid is True

    def test_validate_invalid_ip_exception(self):
        """Test validation when IP parsing raises exception."""
        mock_r = [MagicMock()]
        mock_r[0].address = "not_an_ip"

        invalid, ips = _validate_ip_addresses(mock_r)
        assert invalid is True

    def test_validate_multiple_ips_all_valid(self):
        """Test validation of multiple valid IPs."""
        mock_r = [MagicMock(), MagicMock()]
        mock_r[0].address = "8.8.8.8"
        mock_r[1].address = "1.1.1.1"

        invalid, ips = _validate_ip_addresses(mock_r)
        assert invalid is False
        assert "8.8.8.8" in ips
        assert "1.1.1.1" in ips


class TestFetchMX:
    """Tests for fetch_MX function."""

    @patch("disposablehosts.utils.dns._process_mx_resolution")
    @patch("disposablehosts.utils.dns.resolve_DNS_cached")
    def test_fetch_mx_with_valid_mx(self, mock_resolve, mock_process_mx):
        """Test fetching MX with valid MX record."""
        mock_process_mx.return_value = ({"mail.example.com"}, False)

        # For A record resolution
        mock_answer = MagicMock()
        mock_r = MagicMock()
        mock_r.address = "8.8.8.8"
        mock_answer.__iter__ = lambda self: iter([mock_r])
        mock_resolve.return_value = mock_answer

        result = fetch_MX("example.com")
        assert result == ("example.com", True)

    @patch("disposablehosts.utils.dns._process_mx_resolution")
    def test_fetch_mx_with_invalid_mx(self, mock_process_mx):
        """Test fetching MX with invalid MX record (localhost or dot)."""
        mock_process_mx.return_value = ({"localhost"}, True)

        result = fetch_MX("example.com")
        assert result == ("example.com", False)

    @patch("disposablehosts.utils.dns._process_mx_resolution")
    @patch("disposablehosts.utils.dns.resolve_DNS_cached")
    def test_fetch_mx_no_mx_fallback_to_a(self, mock_resolve, mock_process_mx):
        """Test fetching MX with no MX record, fallback to A record."""
        # First call for MX returns empty set, triggers fallback to A
        mock_process_mx.return_value = (set(), False)

        mock_answer = MagicMock()
        mock_r = MagicMock()
        mock_r.address = "8.8.8.8"
        mock_answer.__iter__ = lambda self: iter([mock_r])
        mock_resolve.return_value = mock_answer

        result = fetch_MX("example.com")
        assert result == ("example.com", True)

    @patch("disposablehosts.utils.dns._process_mx_resolution")
    def test_fetch_mx_no_records(self, mock_process_mx):
        """Test fetching MX with no records at all."""
        mock_process_mx.return_value = (None, False)

        result = fetch_MX("example.com")
        assert result == ("example.com", False)

    @patch("disposablehosts.utils.dns._process_mx_resolution")
    @patch("disposablehosts.utils.dns.resolve_DNS_cached")
    def test_fetch_mx_with_custom_nameservers(self, mock_resolve, mock_process_mx):
        """Test fetching MX with custom nameservers."""
        mock_process_mx.return_value = ({"mail.example.com"}, False)

        mock_answer = MagicMock()
        mock_r = MagicMock()
        mock_r.address = "8.8.8.8"
        mock_answer.__iter__ = lambda self: iter([mock_r])
        mock_resolve.return_value = mock_answer

        result = fetch_MX("example.com", nameservers=["8.8.8.8"], dnsport=53, resolver_timeout=10)
        assert result == ("example.com", True)

    @patch("disposablehosts.utils.dns._process_mx_resolution")
    @patch("disposablehosts.utils.dns.resolve_DNS_cached")
    def test_fetch_mx_private_ip_rejected(self, mock_resolve, mock_process_mx):
        """Test fetching MX rejects private IPs."""
        mock_process_mx.return_value = ({"mail.example.com"}, False)

        # Return private IP
        mock_answer = MagicMock()
        mock_r = MagicMock()
        mock_r.address = "192.168.1.1"
        mock_answer.__iter__ = lambda self: iter([mock_r])
        mock_resolve.return_value = mock_answer

        result = fetch_MX("example.com")
        assert result == ("example.com", False)

    @patch("disposablehosts.utils.dns._process_mx_resolution")
    @patch("disposablehosts.utils.dns.resolve_DNS_cached")
    def test_fetch_mx_string_response(self, mock_resolve, mock_process_mx):
        """Test fetching MX when resolve returns string error."""
        mock_process_mx.return_value = (None, False)
        mock_resolve.return_value = "timeout"

        result = fetch_MX("example.com")
        assert result == ("example.com", False)

    @patch("disposablehosts.utils.dns._process_mx_resolution")
    @patch("disposablehosts.utils.dns.resolve_DNS_cached")
    def test_fetch_mx_no_response(self, mock_resolve, mock_process_mx):
        """Test fetching MX when resolve returns None/falsy."""
        mock_process_mx.return_value = (None, False)
        mock_resolve.return_value = None

        result = fetch_MX("example.com")
        assert result == ("example.com", False)


import pytest
