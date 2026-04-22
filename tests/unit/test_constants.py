"""Unit tests for the constants module."""

from disposablehosts.constants import (
    DISPOSABLE_GREYLIST_URL,
    DISPOSABLE_WHITELIST_URL,
    DOMAIN_RE,
    SHA1_RE,
    generate_random_string,
)


class TestRegexPatterns:
    """Tests for regex patterns."""

    def test_domain_re_valid(self):
        """Test DOMAIN_RE with valid domains."""
        assert DOMAIN_RE.match("example.com")
        assert DOMAIN_RE.match("sub.example.co.uk")
        assert DOMAIN_RE.match("my-domain.org")

    def test_domain_re_invalid(self):
        """Test DOMAIN_RE with invalid domains."""
        assert not DOMAIN_RE.match("not_a_domain")
        assert not DOMAIN_RE.match("example")
        assert not DOMAIN_RE.match(".example.com")

    def test_sha1_re(self):
        """Test SHA1_RE pattern."""
        assert SHA1_RE.match("a" * 40)
        assert SHA1_RE.match("0123456789abcdef" * 2 + "0123456789")  # 40 hex chars
        assert not SHA1_RE.match("g" * 40)  # Invalid hex
        assert not SHA1_RE.match("a" * 39)  # Too short


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_generate_random_string_length(self):
        """Test generate_random_string returns correct length."""
        result = generate_random_string(8)
        assert len(result) == 8

    def test_generate_random_string_content(self):
        """Test generate_random_string returns lowercase letters."""
        result = generate_random_string(10)
        assert result.islower()
        assert result.isalpha()


class TestUrls:
    """Tests for URL constants."""

    def test_whitelist_url(self):
        """Test whitelist URL is valid."""
        assert DISPOSABLE_WHITELIST_URL.startswith("https://")
        assert "whitelist" in DISPOSABLE_WHITELIST_URL

    def test_greylist_url(self):
        """Test greylist URL is valid."""
        assert DISPOSABLE_GREYLIST_URL.startswith("https://")
        assert "greylist" in DISPOSABLE_GREYLIST_URL
