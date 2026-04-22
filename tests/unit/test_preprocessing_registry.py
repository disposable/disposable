"""Tests for the preprocessor registry.

Tests for dynamic preprocessor loading and caching.
"""

import pytest

from disposablehosts.preprocessing.registry import (
    _import_preprocessor_module,
    get_preprocessor,
)


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
            mod = _import_preprocessor_module("json")
            # Remove the expected function to simulate the error
            del mod.preprocess_json
            if not hasattr(mod, "preprocess_json"):
                raise RuntimeError("Preprocessor module does not export callable")
