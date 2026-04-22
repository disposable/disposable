"""Tests for file-based preprocessing.

Tests for plain text file preprocessing including:
- Domain lists
- Whitelist/greylist files
- Comment/empty line handling
"""

from disposablehosts.preprocessing.file import preprocess_file


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

    def test_custom_encoding(self):
        """Test file preprocessing with custom encoding."""
        data = "example.com\ntëst.org\n".encode("utf-8")
        result = preprocess_file(data, encoding="utf-8")
        assert "example.com" in result
        assert "tëst.org" in result
