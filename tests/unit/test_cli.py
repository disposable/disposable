"""Unit tests for the CLI module."""

import sys
from unittest.mock import MagicMock, patch


from disposablehosts.cli import main


class TestCLIArguments:
    """Tests for CLI argument parsing."""

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_no_args(self, mock_exit, mock_generator_class):
        """Test main with no arguments."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable"]):
            main()

        mock_generator_class.assert_called_once()
        mock_generator.generate.assert_called_once()
        mock_generator.write_to_file.assert_called_once()
        mock_exit.assert_called_with(0)

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_generate_fails(self, mock_exit, mock_generator_class):
        """Test main when generate returns False."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = False
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable"]):
            main()

        mock_exit.assert_called_with(1)

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_dns_verify(self, mock_exit, mock_generator_class):
        """Test main with --dns-verify flag."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--dns-verify"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("dns_verify") is True

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_source_map(self, mock_exit, mock_generator_class):
        """Test main with --source-map flag."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--source-map"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("source_map") is True

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_quiet(self, mock_exit, mock_generator_class):
        """Test main with --quiet flag."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "-q"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("verbose") is False

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_debug(self, mock_exit, mock_generator_class):
        """Test main with --debug flag."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "-D"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("debug") is True

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_max_retry(self, mock_exit, mock_generator_class):
        """Test main with --max-retry option."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--max-retry", "50"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("max_retry") == 50

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_dns_threads(self, mock_exit, mock_generator_class):
        """Test main with --dns-threads option."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--dns-threads", "20"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("dns_threads") == 20

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_dns_timeout(self, mock_exit, mock_generator_class):
        """Test main with --dns-timeout option."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--dns-timeout", "30.5"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("dns_timeout") == 30.5

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_nameservers(self, mock_exit, mock_generator_class):
        """Test main with --ns option."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--ns", "8.8.8.8", "--ns", "1.1.1.1"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("nameservers") == ["8.8.8.8", "1.1.1.1"]

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_dnsport(self, mock_exit, mock_generator_class):
        """Test main with --dnsport option."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--dnsport", "5353"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("dnsport") == 5353

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_list_sources(self, mock_exit, mock_generator_class):
        """Test main with --list-sources flag."""
        mock_generator = MagicMock()
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--list-sources"]):
            main()

        mock_generator.list_sources.assert_called_once()
        mock_generator.generate.assert_not_called()
        mock_exit.assert_called_with(1)  # No exit 0 since no domains generated

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_src_filter(self, mock_exit, mock_generator_class):
        """Test main with --src option."""
        mock_generator = MagicMock()
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--src", "some_source"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("src_filter") == "some_source"
        mock_exit.assert_called_with(0)

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_whitelist(self, mock_exit, mock_generator_class):
        """Test main with --whitelist option."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--whitelist", "custom_whitelist.txt"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("whitelist") == "custom_whitelist.txt"

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_greylist(self, mock_exit, mock_generator_class):
        """Test main with --greylist option."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--greylist", "custom_greylist.txt"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("greylist") == "custom_greylist.txt"

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_file(self, mock_exit, mock_generator_class):
        """Test main with --file option."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--file", "custom_domains.txt"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("file") == "custom_domains.txt"

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_skip_scrape(self, mock_exit, mock_generator_class):
        """Test main with --skip-scrape flag."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--skip-scrape"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("skip_scrape") is True

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_skip_src(self, mock_exit, mock_generator_class):
        """Test main with --skip-src option."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--skip-src", "src1", "--skip-src", "src2"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("skip_src") == ["src1", "src2"]

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_strict(self, mock_exit, mock_generator_class):
        """Test main with --strict flag."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--strict"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("strict") is True

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_dedicated_strict(self, mock_exit, mock_generator_class):
        """Test main with --dedicated-strict flag."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--dedicated-strict"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("dedicated_strict") is True
        mock_generator.add_greylist.assert_called_once()

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_list_no_mx(self, mock_exit, mock_generator_class):
        """Test main with --list-no-mx flag."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--list-no-mx"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("list_no_mx") is True

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_main_with_add_free_mailservices(self, mock_exit, mock_generator_class):
        """Test main with --add-free-mailservices flag."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--add-free-mailservices"]):
            main()

        call_args = mock_generator_class.call_args[0][0]
        assert call_args.get("free_mailservices") is True


class TestCLIDedicatedStrict:
    """Tests for dedicated strict mode behavior."""

    @patch("disposablehosts.cli.disposableHostGenerator")
    @patch("disposablehosts.cli.sys.exit")
    def test_dedicated_strict_writes_two_files(self, mock_exit, mock_generator_class):
        """Test that dedicated strict mode writes both files."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = True
        mock_generator_class.return_value = mock_generator

        with patch.object(sys, "argv", ["disposable", "--dedicated-strict"]):
            main()

        # First write is normal, second is strict file
        assert mock_generator.write_to_file.call_count == 2
        assert mock_generator.out_file == "domains_strict"
