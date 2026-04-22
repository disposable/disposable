"""Output and generation flow tests for the generator module.

Tests cover:
- File writing (write_to_file)
- Generation flow (generate)
- Logging results (_log_generation_results)
"""

import json
from pathlib import Path
from unittest.mock import patch

from disposablehosts.generator import disposableHostGenerator


class TestWriteToFile:
    """Tests for write_to_file method."""

    def test_write_to_file_basic(self, tmp_path: Path):
        """Test basic file writing."""
        gen = disposableHostGenerator()
        gen.out_file = str(tmp_path / "domains")
        gen.domains = {"example.com", "test.org"}
        gen.sha1 = {"hash1"}

        gen.write_to_file()

        domains_txt = (tmp_path / "domains.txt").read_text()
        assert "example.com" in domains_txt
        assert "test.org" in domains_txt

    def test_write_to_file_with_source_map(self, tmp_path: Path):
        """Test file writing with source map."""
        gen = disposableHostGenerator({"source_map": True})
        gen.out_file = str(tmp_path / "domains")
        gen.domains = {"example.com"}
        gen.source_map = {"https://example.com": ["example.com"]}
        gen.sha1 = {"hash1"}

        gen.write_to_file()

        source_map = (tmp_path / "domains_source_map.txt").read_text()
        assert "https://example.com" in source_map


class TestWriteToFileOptions:
    """Additional tests for write_to_file."""

    def test_write_with_sha1_only(self, tmp_path: Path):
        """Test writing with SHA1 only."""
        gen = disposableHostGenerator()
        gen.out_file = str(tmp_path / "domains")
        gen.domains = set()
        gen.sha1 = {"hash1"}

        gen.write_to_file()

        sha1_file = tmp_path / "domains_sha1.txt"
        assert sha1_file.exists()
        assert "hash1" in sha1_file.read_text()

    def test_write_json_output(self, tmp_path: Path):
        """Test writing JSON output."""
        gen = disposableHostGenerator()
        gen.out_file = str(tmp_path / "domains")
        gen.domains = {"example.com"}
        gen.sha1 = set()

        gen.write_to_file()

        json_file = tmp_path / "domains.json"
        assert json_file.exists()

        data = json.loads(json_file.read_text())
        assert "example.com" in data


class TestWriteToFileExtended:
    """Extended tests for write_to_file with no_mx output."""

    def test_write_to_file_no_mx_filter(self, tmp_path):
        """Test writing MX-filtered output when no_mx is set."""
        gen = disposableHostGenerator()
        gen.out_file = str(tmp_path / "domains")
        gen.domains = {"example.com", "invalid.com", "test.org"}
        gen.sha1 = set()
        gen.no_mx = ["invalid.com"]

        gen.write_to_file()

        # Regular output should have all domains
        domains_txt = (tmp_path / "domains.txt").read_text()
        assert "example.com" in domains_txt
        assert "invalid.com" in domains_txt
        assert "test.org" in domains_txt

        # MX-filtered output should exclude invalid.com
        mx_txt = (tmp_path / "domains_mx.txt").read_text()
        assert "example.com" in mx_txt
        assert "invalid.com" not in mx_txt
        assert "test.org" in mx_txt

        # JSON version should also be filtered
        mx_json = json.loads((tmp_path / "domains_mx.json").read_text())
        assert "invalid.com" not in mx_json
        assert "example.com" in mx_json

    def test_write_to_file_no_mx_empty(self, tmp_path):
        """Test that MX files are not created when no_mx is empty."""
        gen = disposableHostGenerator()
        gen.out_file = str(tmp_path / "domains")
        gen.domains = {"example.com"}
        gen.sha1 = set()
        gen.no_mx = []

        gen.write_to_file()

        # MX files should not exist
        assert not (tmp_path / "domains_mx.txt").exists()
        assert not (tmp_path / "domains_mx.json").exists()


class TestLogResults:
    """Tests for _log_generation_results."""

    @patch.object(disposableHostGenerator, "read_files")
    @patch("disposablehosts.generator.logging.info")
    def test_log_quiet(self, mock_info, mock_read):
        """Test logging when quiet."""
        gen = disposableHostGenerator({"verbose": False})
        result = gen._log_generation_results()
        assert result is True

    @patch.object(disposableHostGenerator, "read_files")
    @patch("disposablehosts.generator.logging.info")
    def test_log_no_changes(self, mock_info, mock_read):
        """Test logging with no changes."""
        gen = disposableHostGenerator({"verbose": True})
        gen.domains = {"example.com"}
        gen.old_domains = {"example.com"}
        gen.sha1 = {"hash1"}
        gen.old_sha1 = {"hash1"}
        result = gen._log_generation_results()
        assert result is False

    @patch.object(disposableHostGenerator, "read_files")
    @patch("disposablehosts.generator.logging.info")
    def test_log_with_changes(self, mock_info, mock_read):
        """Test logging with changes."""
        gen = disposableHostGenerator({"verbose": True})
        gen.domains = {"example.com", "new.com"}
        gen.old_domains = {"example.com"}
        gen.sha1 = {"hash1"}
        gen.old_sha1 = {"hash1"}
        result = gen._log_generation_results()
        assert result is True


class TestGenerate:
    """Tests for generate method."""

    @patch.object(disposableHostGenerator, "_fetch_sources")
    @patch.object(disposableHostGenerator, "_apply_whitelist")
    @patch.object(disposableHostGenerator, "_verify_mx_records")
    @patch.object(disposableHostGenerator, "_log_generation_results")
    def test_generate_success(self, mock_log, mock_verify, mock_apply, mock_fetch):
        """Test successful generation."""
        mock_log.return_value = True
        gen = disposableHostGenerator()
        result = gen.generate()
        assert result is True

    @patch.object(disposableHostGenerator, "_fetch_sources")
    @patch.object(disposableHostGenerator, "_apply_whitelist")
    @patch.object(disposableHostGenerator, "_verify_mx_records")
    @patch.object(disposableHostGenerator, "_log_generation_results")
    def test_generate_no_changes(self, mock_log, mock_verify, mock_apply, mock_fetch):
        """Test generation with no changes."""
        mock_log.return_value = False
        gen = disposableHostGenerator()
        result = gen.generate()
        assert result is False


class TestGenerateFlowExtended:
    """Extended tests for generate method flow."""

    @patch.object(disposableHostGenerator, "_fetch_sources")
    @patch.object(disposableHostGenerator, "_apply_whitelist")
    @patch.object(disposableHostGenerator, "_verify_mx_records")
    @patch.object(disposableHostGenerator, "_log_generation_results")
    def test_generate_with_changes(self, mock_log, mock_verify, mock_apply, mock_fetch):
        """Test generate when there are changes."""
        mock_log.return_value = True
        gen = disposableHostGenerator()
        result = gen.generate()
        assert result is True

    @patch.object(disposableHostGenerator, "_fetch_sources")
    @patch.object(disposableHostGenerator, "_apply_whitelist")
    @patch.object(disposableHostGenerator, "_verify_mx_records")
    @patch.object(disposableHostGenerator, "_log_generation_results")
    def test_generate_no_changes_returns_false(self, mock_log, mock_verify, mock_apply, mock_fetch):
        """Test generate returns False when no changes."""
        mock_log.return_value = False
        gen = disposableHostGenerator()
        result = gen.generate()
        assert result is False
