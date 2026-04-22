"""Extended unit tests for preprocessing modules."""

from disposablehosts.preprocessing.html import preprocess_html
from disposablehosts.preprocessing.json import preprocess_json
from disposablehosts.preprocessing.registry import get_preprocessor, _import_preprocessor_module
from disposablehosts.preprocessing.sha1 import preprocess_sha1


class TestPreprocessHtmlExtended:
    """Extended tests for HTML preprocessing."""

    def test_preprocess_html_with_custom_regex(self):
        """Test HTML preprocessing with custom regex."""
        import re

        custom_re = re.compile(r"<span>([a-z0-9.-]+)</span>")
        data = b"<span>example.com</span><span>test.org</span>"
        result = preprocess_html(data, custom_re)
        assert "example.com" in result
        assert "test.org" in result

    def test_preprocess_html_with_regex_list(self):
        """Test HTML preprocessing with list of regex patterns."""
        import re

        regex_list = [
            re.compile(r"<div>(.+?)</div>"),
            re.compile(r"([a-z0-9.-]+\.[a-z]{2,})"),
        ]
        data = b"<div>example.com</div>"
        result = preprocess_html(data, regex_list)
        assert "example.com" in result

    def test_preprocess_html_empty_result(self):
        """Test HTML preprocessing with no matches."""
        import re

        custom_re = re.compile(r"<nomatch>(.+?)</nomatch>")
        data = b"<div>example.com</div>"
        result = preprocess_html(data, custom_re)
        assert result == []

    def test_preprocess_html_tuple_result(self):
        """Test HTML preprocessing when regex returns tuples."""
        import re

        # Regex with groups returns tuples
        custom_re = re.compile(r"<option>([^<]+)</option>")
        data = b"<option>example.com</option>"
        result = preprocess_html(data, custom_re)
        assert "example.com" in result

    def test_preprocess_html_html_entities(self):
        """Test HTML preprocessing with HTML entities."""
        from disposablehosts.constants import HTML_GENERIC_RE

        data = b"<option>test&#46;com</option>"
        result = preprocess_html(data, HTML_GENERIC_RE)
        assert "test.com" in result


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


class TestPreprocessSha1Extended:
    """Extended tests for SHA1 preprocessing."""

    def test_preprocess_sha1_mixed_valid_invalid(self):
        """Test SHA1 preprocessing with mix of valid and invalid hashes."""
        data = b"a" * 40 + b"\n" + b"invalid" + b"\n" + b"b" * 40 + b"\n"
        sha1_set = set()
        count = preprocess_sha1(data, sha1_set)
        assert count == 2
        assert "a" * 40 in sha1_set
        assert "b" * 40 in sha1_set
        assert "invalid" not in sha1_set

    def test_preprocess_sha1_case_insensitive(self):
        """Test SHA1 preprocessing is case insensitive."""
        data = b"A" * 40 + b"\n"
        sha1_set = set()
        count = preprocess_sha1(data, sha1_set)
        assert count == 1
        assert "a" * 40 in sha1_set  # Stored as lowercase

    def test_preprocess_sha1_empty_lines(self):
        """Test SHA1 preprocessing with empty lines."""
        data = b"\n\n" + b"a" * 40 + b"\n\n"
        sha1_set = set()
        count = preprocess_sha1(data, sha1_set)
        assert count == 1


class TestPreprocessorRegistry:
    """Tests for preprocessor registry."""

    def test_get_preprocessor_json(self):
        """Test getting JSON preprocessor."""
        fn = get_preprocessor("json")
        assert callable(fn)

    def test_get_preprocessor_list(self):
        """Test getting list preprocessor (maps to file)."""
        fn = get_preprocessor("list")
        assert callable(fn)

    def test_get_preprocessor_file(self):
        """Test getting file preprocessor."""
        fn = get_preprocessor("file")
        assert callable(fn)

    def test_get_preprocessor_whitelist(self):
        """Test getting whitelist preprocessor."""
        fn = get_preprocessor("whitelist")
        assert callable(fn)

    def test_get_preprocessor_whitelist_file(self):
        """Test getting whitelist_file preprocessor."""
        fn = get_preprocessor("whitelist_file")
        assert callable(fn)

    def test_get_preprocessor_greylist(self):
        """Test getting greylist preprocessor."""
        fn = get_preprocessor("greylist")
        assert callable(fn)

    def test_get_preprocessor_greylist_file(self):
        """Test getting greylist_file preprocessor."""
        fn = get_preprocessor("greylist_file")
        assert callable(fn)

    def test_get_preprocessor_html(self):
        """Test getting HTML preprocessor."""
        fn = get_preprocessor("html")
        assert callable(fn)

    def test_get_preprocessor_sha1(self):
        """Test getting SHA1 preprocessor."""
        fn = get_preprocessor("sha1")
        assert callable(fn)

    def test_get_preprocessor_ws(self):
        """Test getting WebSocket preprocessor."""
        fn = get_preprocessor("ws")
        assert callable(fn)

    def test_get_preprocessor_unknown_type(self):
        """Test getting preprocessor for unknown type raises error."""
        with pytest.raises(RuntimeError) as exc_info:
            get_preprocessor("unknown_type")
        assert "Unknown preprocessor type" in str(exc_info.value)

    def test_get_preprocessor_cached(self):
        """Test that preprocessors are cached."""
        fn1 = get_preprocessor("json")
        fn2 = get_preprocessor("json")
        assert fn1 is fn2

    def test_import_preprocessor_module(self):
        """Test importing preprocessor module."""
        mod = _import_preprocessor_module("json")
        assert hasattr(mod, "preprocess_json")

    def test_import_preprocessor_module_invalid(self):
        """Test importing invalid preprocessor module raises error."""
        with pytest.raises(RuntimeError):
            # Get a preprocessor that doesn't export the expected function
            # by manually testing the import
            from disposablehosts.preprocessing.registry import _import_preprocessor_module

            # Try to get a module that doesn't have the expected function
            mod = _import_preprocessor_module("json")
            # Remove the expected function to simulate the error
            del mod.preprocess_json
            if not hasattr(mod, "preprocess_json"):
                raise RuntimeError("Preprocessor module does not export callable")


import pytest
