"""Tests for JSON preprocessing.

Tests for extracting domains from JSON data including:
- JSON arrays
- Domain/email keyed objects
- BOM encoding handling
- Invalid JSON handling
"""

from disposablehosts.preprocessing.json import preprocess_json


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


class TestPreprocessJsonExtended:
    """Extended tests for JSON preprocessing."""

    def test_preprocess_json_with_email_key(self):
        """Test JSON preprocessing with email key."""
        data = b'{"email": "user@example.com"}'
        result = preprocess_json(data)
        assert result == ["example.com"]

    def test_preprocess_json_email_without_at(self):
        """Test JSON preprocessing with email key but no @ symbol."""
        data = b'{"email": "invalid_email"}'
        result = preprocess_json(data)
        # Regex extracts 'email' part from 'invalid_email'
        assert result == ["email"]

    def test_preprocess_json_bom_encoding(self):
        """Test JSON preprocessing with UTF-8 BOM."""
        # Create data with BOM
        data = b'\xef\xbb\xbf["example.com", "test.org"]'
        result = preprocess_json(data)
        assert result == ["example.com", "test.org"]

    def test_preprocess_json_invalid_json(self):
        """Test JSON preprocessing with invalid JSON."""
        data = b"not valid json"
        result = preprocess_json(data)
        assert result is None

    def test_preprocess_json_not_list_result(self):
        """Test JSON preprocessing when result is not a list."""
        data = b'{"key": "value"}'
        result = preprocess_json(data)
        assert result is None

    def test_preprocess_json_filter_non_string(self):
        """Test JSON preprocessing filters non-string items."""
        data = b'["example.com", 123, null, "test.org"]'
        result = preprocess_json(data)
        assert "example.com" in result
        assert "test.org" in result
        assert 123 not in result
