"""Unit tests for the generator module."""

from disposablehosts.generator import disposableHostGenerator


class TestDisposableHostGenerator:
    """Tests for the disposableHostGenerator class."""

    def test_init_default_options(self):
        """Test initialization with default options."""
        gen = disposableHostGenerator()
        assert gen.out_file == "domains"
        assert gen.domains == set()
        assert gen.sha1 == set()

    def test_init_custom_options(self):
        """Test initialization with custom options."""
        gen = disposableHostGenerator({"verbose": True}, "custom_output")
        assert gen.out_file == "custom_output"
        assert gen.options.get("verbose") is True

    def test_check_valid_domains_valid(self):
        """Test domain validation with valid domains."""
        gen = disposableHostGenerator()
        assert gen.check_valid_domains("example.com") is True
        assert gen.check_valid_domains("sub.example.com") is True

    def test_check_valid_domains_invalid(self):
        """Test domain validation with invalid domains."""
        gen = disposableHostGenerator()
        assert gen.check_valid_domains("not_a_domain") is False
        assert gen.check_valid_domains("") is False
        assert gen.check_valid_domains(".example.com") is False
