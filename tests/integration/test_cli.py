"""Integration tests for the CLI."""

import subprocess
import sys
from pathlib import Path


class TestCliHelp:
    """Tests for CLI help output."""

    def test_cli_help_via_module(self):
        """Test CLI help output via module execution."""
        result = subprocess.run(
            [sys.executable, "-m", "disposablehosts", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Generate list of disposable mail hosts" in result.stdout

    def test_cli_list_sources(self):
        """Test CLI list-sources option."""
        # Run with list-sources (should not require network)
        result = subprocess.run(
            [sys.executable, "-c", "from disposablehosts import disposableHostGenerator; g = disposableHostGenerator({'verbose': True}); g.list_sources()"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent.parent),
        )
        assert result.returncode == 0


class TestBackwardCompat:
    """Tests for backward compatibility."""

    def test_import_from_root(self):
        """Test importing from the root disposable module."""
        result = subprocess.run(
            [sys.executable, "-c", "import sys; sys.path.insert(0, 'src'); from disposable import disposableHostGenerator; print('OK')"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent.parent),
        )
        assert result.returncode == 0
        assert "OK" in result.stdout

    def test_import_from_package(self):
        """Test importing from the disposablehosts package."""
        result = subprocess.run(
            [sys.executable, "-c", "import sys; sys.path.insert(0, 'src'); from disposablehosts import disposableHostGenerator, main; print('OK')"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent.parent),
        )
        assert result.returncode == 0
        assert "OK" in result.stdout
