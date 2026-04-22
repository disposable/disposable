"""Additional tests for generator to reach 85% coverage."""

from pathlib import Path
from unittest.mock import patch


from disposablehosts.generator import disposableHostGenerator


class TestGeneratorOptions:
    """Tests for various generator options."""

    def test_init_with_verbose(self):
        """Test verbose option."""
        gen = disposableHostGenerator({"verbose": True})
        assert gen.options.get("verbose") is True

    def test_init_with_debug(self):
        """Test debug option."""
        gen = disposableHostGenerator({"debug": True})
        assert gen.options.get("debug") is True

    def test_init_with_source_map(self):
        """Test source_map option."""
        gen = disposableHostGenerator({"source_map": True})
        assert gen.options.get("source_map") is True

    def test_init_with_whitelist(self):
        """Test custom whitelist."""
        gen = disposableHostGenerator({"whitelist": "custom.txt"})
        wl = next((s for s in gen.sources if s.get("type") == "whitelist_file"), None)
        assert wl is not None
        assert wl["src"] == "custom.txt"

    def test_init_with_greylist(self):
        """Test custom greylist."""
        gen = disposableHostGenerator({"greylist": "custom.txt"})
        gl = next((s for s in gen.sources if s.get("type") == "greylist_file"), None)
        assert gl is not None
        assert gl["src"] == "custom.txt"

    def test_init_with_file(self):
        """Test custom file."""
        gen = disposableHostGenerator({"file": "custom.txt"})
        f = next((s for s in gen.sources if s.get("type") == "file"), None)
        assert f is not None
        assert f["src"] == "custom.txt"

    def test_init_skip_scrape(self):
        """Test skip_scrape option."""
        gen = disposableHostGenerator({"skip_scrape": True})
        assert gen.options.get("skip_scrape") is True

    def test_init_strict(self):
        """Test strict option."""
        gen = disposableHostGenerator({"strict": True})
        assert gen.options.get("strict") is True

    def test_init_dedicated_strict(self):
        """Test dedicated_strict option."""
        gen = disposableHostGenerator({"dedicated_strict": True})
        assert gen.options.get("dedicated_strict") is True

    def test_init_list_no_mx(self):
        """Test list_no_mx option."""
        gen = disposableHostGenerator({"list_no_mx": True})
        assert gen.options.get("list_no_mx") is True


class TestFetchSources:
    """Tests for _fetch_sources method."""

    @patch.object(disposableHostGenerator, "process")
    def test_fetch_sources_with_src_filter(self, mock_process):
        """Test fetch sources with src_filter."""
        gen = disposableHostGenerator({"src_filter": "test_source"})
        gen._fetch_sources()
        assert mock_process.called is False

    @patch.object(disposableHostGenerator, "_should_skip_source")
    @patch.object(disposableHostGenerator, "process")
    def test_fetch_sources_skip_disabled(self, mock_process, mock_skip):
        """Test fetch sources with disabled source."""
        mock_skip.return_value = True
        gen = disposableHostGenerator()
        gen._fetch_sources()


class TestVerifyMXRecords:
    """Tests for _verify_mx_records method."""

    @patch("disposablehosts.generator.fetch_MX")
    def test_verify_mx_disabled(self, mock_fetch):
        """Test verify when disabled."""
        gen = disposableHostGenerator({"dns_verify": False})
        gen.domains = {"example.com"}
        gen._verify_mx_records()
        assert gen.no_mx == []
        mock_fetch.assert_not_called()

    @patch("disposablehosts.generator.fetch_MX")
    def test_verify_mx_empty_domains(self, mock_fetch):
        """Test verify with empty domains."""
        gen = disposableHostGenerator({"dns_verify": True})
        gen.domains = set()
        gen._verify_mx_records()
        assert gen.no_mx == []


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
        import json

        data = json.loads(json_file.read_text())
        assert "example.com" in data
