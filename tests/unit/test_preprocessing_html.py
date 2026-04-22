"""Tests for HTML preprocessing.

Tests for extracting domains from HTML data including:
- Option tag extraction
- Custom regex patterns
- HTML entities
"""

import re

from disposablehosts.constants import HTML_GENERIC_RE
from disposablehosts.preprocessing.html import preprocess_html


class TestPreprocessHtml:
    """Tests for HTML preprocessing."""

    def test_generic_option_extraction(self):
        """Test extracting domains from option tags."""
        data = b"<option>@example.com (PW)</option><option>test.org</option>"
        result = preprocess_html(data, HTML_GENERIC_RE)
        result_set = set(result)
        assert "example.com" in result_set
        assert "test.org" in result_set


class TestPreprocessHtmlExtended:
    """Extended tests for HTML preprocessing."""

    def test_preprocess_html_with_custom_regex(self):
        """Test HTML preprocessing with custom regex."""
        custom_re = re.compile(r"<span>([a-z0-9.-]+)</span>")
        data = b"<span>example.com</span><span>test.org</span>"
        result = preprocess_html(data, custom_re)
        assert "example.com" in result
        assert "test.org" in result

    def test_preprocess_html_with_regex_list(self):
        """Test HTML preprocessing with list of regex patterns."""
        regex_list = [
            re.compile(r"<div>(.+?)</div>"),
            re.compile(r"([a-z0-9.-]+\.[a-z]{2,})"),
        ]
        data = b"<div>example.com</div>"
        result = preprocess_html(data, regex_list)
        assert "example.com" in result

    def test_preprocess_html_empty_result(self):
        """Test HTML preprocessing with no matches."""
        custom_re = re.compile(r"<nomatch>(.+?)</nomatch>")
        data = b"<div>example.com</div>"
        result = preprocess_html(data, custom_re)
        assert result == []

    def test_preprocess_html_tuple_result(self):
        """Test HTML preprocessing when regex returns tuples."""
        # Regex with groups returns tuples
        custom_re = re.compile(r"<option>([^<]+)</option>")
        data = b"<option>example.com</option>"
        result = preprocess_html(data, custom_re)
        assert "example.com" in result

    def test_preprocess_html_html_entities(self):
        """Test HTML preprocessing with HTML entities."""
        data = b"<option>test&#46;com</option>"
        result = preprocess_html(data, HTML_GENERIC_RE)
        assert "test.com" in result
