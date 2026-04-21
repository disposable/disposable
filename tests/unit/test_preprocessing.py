"""Unit tests for the preprocessing modules."""

from disposablehosts.preprocessing.file import preprocess_file
from disposablehosts.preprocessing.json import preprocess_json
from disposablehosts.preprocessing.html import preprocess_html
from disposablehosts.preprocessing.sha1 import preprocess_sha1


class TestPreprocessFile:
    """Tests for file preprocessing."""

    def test_simple_list(self):
        """Test processing a simple domain list."""
        data = b"example.com\ntest.org\n"
        result = preprocess_file(data)
        assert result == ["example.com", "test.org"]

    def test_skips_comments(self):
        """Test that comments and empty lines are skipped."""
        data = b"# Comment\nexample.com\n\ntest.org\n"
        result = preprocess_file(data)
        assert result == ["example.com", "test.org"]


class TestPreprocessJson:
    """Tests for JSON preprocessing."""

    def test_simple_array(self):
        """Test processing a JSON array."""
        data = b'["example.com", "test.org"]'
        result = preprocess_json(data)
        assert result == ["example.com", "test.org"]

    def test_domains_object(self):
        """Test processing JSON with domains key."""
        data = b'{"domains": ["example.com", "test.org"]}'
        result = preprocess_json(data)
        assert result == ["example.com", "test.org"]

    def test_empty_data(self):
        """Test processing empty data."""
        data = b"{}"
        result = preprocess_json(data)
        assert result is None


class TestPreprocessHtml:
    """Tests for HTML preprocessing."""

    def test_generic_option_extraction(self):
        """Test extracting domains from option tags."""
        from disposablehosts.constants import HTML_GENERIC_RE

        data = b"<option>@example.com (PW)</option><option>test.org</option>"
        result = preprocess_html(data, HTML_GENERIC_RE)
        assert "example.com" in result
        assert "test.org" in result


class TestPreprocessSha1:
    """Tests for SHA1 preprocessing."""

    def test_valid_hashes(self):
        """Test processing valid SHA1 hashes."""
        data = b"a" * 40 + b"\n" + b"b" * 40 + b"\n"
        sha1_set = set()
        count = preprocess_sha1(data, sha1_set)
        assert count == 2
        assert len(sha1_set) == 2

    def test_invalid_hashes_skipped(self):
        """Test that invalid hashes are skipped."""
        data = b"not_a_hash\n" + b"g" * 40 + b"\n"  # Invalid hex
        sha1_set = set()
        count = preprocess_sha1(data, sha1_set)
        assert count == 0
