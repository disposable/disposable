"""Tests for file-based remote data fetching.

Tests for local file reading with error handling.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from disposablehosts.remote_data import remoteData


class TestFetchFile:
    """Tests for fetch_file method."""

    def test_fetch_file_reads_bytes(self, tmp_path: Path):
        """fetch_file should return file contents as bytes."""
        target = tmp_path / "domains.txt"
        target.write_text("example.com\n", encoding="utf-8")
        assert remoteData.fetch_file(str(target)) == b"example.com\n"

    def test_fetch_file_ignore_errors(self, tmp_path: Path):
        """fetch_file should return empty bytes when ignore_errors is enabled."""
        missing = tmp_path / "missing.txt"
        assert remoteData.fetch_file(str(missing), ignore_errors=True) == b""

    def test_fetch_file_success(self, tmp_path):
        """Test successful file fetch."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("example.com\n", encoding="utf-8")

        result = remoteData.fetch_file(str(test_file))
        assert result == b"example.com\n"

    def test_fetch_file_not_found_raises(self, tmp_path):
        """Test file fetch raises error when not found."""
        missing_file = tmp_path / "missing.txt"

        with pytest.raises(FileNotFoundError):
            remoteData.fetch_file(str(missing_file))

    def test_fetch_file_not_found_ignore_errors(self, tmp_path):
        """Test file fetch returns empty bytes when ignoring errors."""
        missing_file = tmp_path / "missing.txt"

        result = remoteData.fetch_file(str(missing_file), ignore_errors=True)
        assert result == b""

    @patch("builtins.open")
    def test_fetch_file_io_error(self, mock_open):
        """Test file fetch handles IO error."""
        mock_open.side_effect = IOError("Permission denied")

        with pytest.raises(IOError):
            remoteData.fetch_file("/some/file.txt")

    @patch("builtins.open")
    def test_fetch_file_io_error_ignore_errors(self, mock_open):
        """Test file fetch handles IO error with ignore_errors."""
        mock_open.side_effect = IOError("Permission denied")

        result = remoteData.fetch_file("/some/file.txt", ignore_errors=True)
        assert result == b""
