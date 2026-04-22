"""Tests for SHA1 preprocessing.

Tests for extracting and validating SHA1 hashes from data.
"""

from disposablehosts.preprocessing.sha1 import preprocess_sha1


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
