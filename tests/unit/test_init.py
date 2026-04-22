"""Unit tests for package initialization and main entry point."""

from disposablehosts import __all__, __version__, disposableHostGenerator, main, remoteData


class TestPackageInit:
    """Tests for package initialization."""

    def test_all_exports(self):
        """Test that __all__ exports the expected names."""
        assert "disposableHostGenerator" in __all__
        assert "main" in __all__
        assert "remoteData" in __all__

    def test_version_exists(self):
        """Test that __version__ is set."""
        assert __version__ is not None
        assert isinstance(__version__, str)

    def test_disposable_host_generator_export(self):
        """Test disposableHostGenerator is properly exported."""
        assert disposableHostGenerator is not None

    def test_main_export(self):
        """Test main is properly exported."""
        assert main is not None
        assert callable(main)

    def test_remotedata_export(self):
        """Test remoteData is properly exported."""
        assert remoteData is not None


class TestMainEntryPoint:
    """Tests for __main__ entry point."""

    def test_main_module_import(self):
        """Test that __main__ module can be imported."""
        from disposablehosts.__main__ import main

        assert callable(main)
