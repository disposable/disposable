"""Unit tests for the DNS utilities module."""

from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver

from disposablehosts.utils.dns import (
    _process_mx_resolution,
    _validate_ip_addresses,
    fetch_MX,
)


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

    def test_validate_invalid_ip_exception(self):
        """Test validation when IP parsing raises exception."""
        mock_r = [MagicMock()]
        mock_r[0].address = "not_an_ip"

        invalid, ips = _validate_ip_addresses(mock_r)
        assert invalid is True


class TestFetchMX:
    """Tests for fetch_MX function."""

    @patch("disposablehosts.utils.dns.resolve_DNS_cached")
    def test_fetch_mx_with_records(self, mock_resolve):
        """Test fetching MX with valid records."""
        mock_answer = MagicMock()
        mock_rr = MagicMock()
        mock_rr.exchange.to_text.return_value = "mail.example.com"
        mock_answer.rrset = [mock_rr]
        mock_resolve.return_value = mock_answer

        result = fetch_MX("example.com")
        assert result[0] == "example.com"

    @patch("disposablehosts.utils.dns.resolve_DNS_cached")
    def test_fetch_mx_no_records(self, mock_resolve):
        """Test fetching MX with no records."""
        mock_resolve.return_value = "resolved but no entry"

        result = fetch_MX("example.com")
        assert result == ("example.com", False)


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
