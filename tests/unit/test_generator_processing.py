"""Data processing tests for the generator module.

Tests cover:
- Preprocessing data (_preprocess_data)
- Postprocessing data (_postprocess_data)
- Scrape retry logic
- Fallback domain extraction
"""

import logging
from unittest.mock import patch

from disposablehosts.generator import disposableHostGenerator


class TestPreprocessData:
    """Tests for _preprocess_data method."""

    def test_preprocess_returns_list(self):
        """Test that list data is returned as-is."""
        gen = disposableHostGenerator()
        source = {"type": "json"}
        result = gen._preprocess_data(source, ["domain1.com", "domain2.com"])
        assert result == ["domain1.com", "domain2.com"]

    def test_preprocess_sha1(self):
        """Test SHA1 preprocessing adds to sha1 set."""
        gen = disposableHostGenerator()
        gen.sha1 = set()
        source = {"type": "sha1"}
        data = b"a" * 40 + b"\n" + b"b" * 40 + b"\n"
        result = gen._preprocess_data(source, data)
        assert result == []
        assert len(gen.sha1) == 2

    def test_preprocess_websocket(self):
        """Test WebSocket preprocessing."""
        gen = disposableHostGenerator()
        source = {"type": "ws"}
        data = b"Ddomain1.com,domain2.com"
        result = gen._preprocess_data(source, data)
        assert result == ["domain1.com", "domain2.com"]

    def test_preprocess_json(self):
        """Test JSON preprocessing."""
        gen = disposableHostGenerator()
        source = {"type": "json", "encoding": "utf-8"}
        data = b'["example.com", "test.org"]'
        result = gen._preprocess_data(source, data)
        assert result == ["example.com", "test.org"]

    def test_preprocess_file_types(self):
        """Test file type preprocessing."""
        gen = disposableHostGenerator()
        for fmt in ["whitelist", "list", "file", "whitelist_file", "greylist", "greylist_file"]:
            source = {"type": fmt, "encoding": "utf-8"}
            data = b"# Comment\nexample.com\n\ntest.org\n"
            result = gen._preprocess_data(source, data)
            assert result == ["example.com", "test.org"], f"Failed for format: {fmt}"

    def test_preprocess_mailservices(self):
        """mailservices preprocessing yields only verified-signup whitelist hosts."""
        gen = disposableHostGenerator()
        source = {"type": "whitelist_mailservices"}
        data = b"""{
            "a": {"type": "free", "hosts": ["FreeMail.com", "b.org"]},
            "b": {"type": "paid", "signup_verification": "mobile", "hosts": ["paidmail.com"]},
            "c": {"type": "forwarding", "hosts": ["alias.io"]},
            "d": {"type": "reserved", "hosts": ["example.edu"]},
            "e": {"hosts": ["notype.com"]},
            "f": {"type": "free", "signup_verification": "none", "hosts": ["anonmail.com"]},
            "g": {"type": "free", "signup_verification": ["email"], "hosts": ["mailcheck.com"]},
            "h": {"type": "free", "signup_verification": ["mobile", "email"], "hosts": ["mixedmail.com"]}
        }"""
        assert gen._preprocess_data(source, data) == [
            "b.org",
            "example.edu",
            "freemail.com",
            "paidmail.com",
        ]

    def test_preprocess_mailservices_grey(self):
        """mailservices grey extraction covers forwarding + anonymous-signup providers."""
        from disposablehosts.preprocessing.mailservices import preprocess_mailservices_grey

        data = b"""{
            "a": {"type": "forwarding", "signup_verification": "payment", "hosts": ["alias.io"]},
            "b": {"type": "free", "signup_verification": "none", "hosts": ["anonmail.com"]},
            "c": {"type": "free", "signup_verification": ["email"], "hosts": ["mailcheck.com"]},
            "d": {"type": "free", "signup_verification": ["mobile", "email"], "hosts": ["mixedmail.com"]},
            "e": {"type": "free", "signup_verification": "mobile", "hosts": ["verified.com"]},
            "f": {"type": "free", "hosts": ["unsetmail.com"]},
            "g": {"type": "paid", "signup_verification": "email", "hosts": ["paidanon.com"]},
            "h": {"type": "reserved", "hosts": ["example.edu"]}
        }"""
        assert preprocess_mailservices_grey(data) == [
            "alias.io",
            "anonmail.com",
            "mailcheck.com",
            "mixedmail.com",
            "paidanon.com",
        ]

    def test_preprocess_mailservices_grey_beats_whitelist(self):
        """A host listed as both grey-eligible and whitelist-eligible stays grey."""
        from disposablehosts.preprocessing.mailservices import (
            preprocess_mailservices,
            preprocess_mailservices_grey,
        )

        data = b"""{
            "a": {"type": "free", "signup_verification": "none", "hosts": ["shared.com"]},
            "b": {"type": "free", "signup_verification": "mobile", "hosts": ["shared.com", "ok.com"]}
        }"""
        assert preprocess_mailservices(data) == ["ok.com"]
        assert preprocess_mailservices_grey(data) == ["shared.com"]

    def test_preprocess_mailservices_invalid(self):
        """mailservices preprocessing returns None on bad payloads."""
        gen = disposableHostGenerator()
        source = {"type": "whitelist_mailservices"}
        assert gen._preprocess_data(source, b"not json") is None
        assert gen._preprocess_data(source, b'{"a": {"type": "forwarding", "hosts": ["x.io"]}}') is None

    def test_postprocess_mailservices_whitelists(self):
        """mailservices source fills skip + maintained sets."""
        gen = disposableHostGenerator()
        source = {"type": "whitelist_mailservices", "src": "x"}
        assert gen._postprocess_data(source, b"", ["gmail.com"]) is True
        assert "gmail.com" in gen.skip
        assert "gmail.com" in gen.maintained_whitelist

    def test_postprocess_mailservices_fills_grey(self):
        """mailservices source also populates the grey tier from raw data."""
        gen = disposableHostGenerator()
        source = {"type": "whitelist_mailservices", "src": "x"}
        data = b"""{
            "a": {"type": "forwarding", "hosts": ["alias.io"]},
            "b": {"type": "free", "signup_verification": "none", "hosts": ["anonmail.com"]},
            "c": {"type": "free", "signup_verification": "mobile", "hosts": ["verified.com"]}
        }"""
        assert gen._postprocess_data(source, data, ["verified.com"]) is True
        assert "verified.com" in gen.maintained_whitelist
        assert "verified.com" not in gen.grey
        assert gen.grey == {"alias.io", "anonmail.com"}


class TestPreprocessDataExtended:
    """Extended tests for _preprocess_data with custom encoding."""

    def test_preprocess_html_with_custom_encoding(self):
        """Test HTML preprocessing with custom encoding."""
        gen = disposableHostGenerator()
        source = {"type": "html", "encoding": "iso-8859-1"}
        data = b"<option>example.com</option>"
        result = gen._preprocess_data(source, data)

        # Should process without error
        assert isinstance(result, list)

    def test_preprocess_json_with_custom_encoding(self):
        """Test JSON preprocessing with custom encoding."""
        gen = disposableHostGenerator()
        source = {"type": "json", "encoding": "utf-8"}
        data = b'["example.com"]'
        result = gen._preprocess_data(source, data)

        assert result == ["example.com"]


class TestPostprocessData:
    """Tests for _postprocess_data method."""

    def test_postprocess_whitelist(self):
        """Test postprocessing whitelist source."""
        gen = disposableHostGenerator()
        source = {"type": "whitelist", "src": "whitelist.txt"}
        data = b"example.com\ntest.org"
        lines = ["example.com", "test.org"]
        result = gen._postprocess_data(source, data, lines)
        assert result is True
        assert "example.com" in gen.skip
        assert "test.org" in gen.skip

    def test_postprocess_greylist(self):
        """Test postprocessing greylist source."""
        gen = disposableHostGenerator()
        source = {"type": "greylist", "src": "greylist.txt"}
        data = b"example.com\ntest.org"
        lines = ["example.com", "test.org"]
        result = gen._postprocess_data(source, data, lines)
        assert result is True
        assert "example.com" in gen.grey
        assert "test.org" in gen.grey

    def test_postprocess_with_domains(self):
        """Test postprocessing with valid domains."""
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        data = b"example.com\ntest.org"
        lines = ["example.com", "test.org"]
        result = gen._postprocess_data(source, data, lines)
        assert result == (2, 2)
        assert "example.com" in gen.domains
        assert "test.org" in gen.domains

    def test_postprocess_with_scrape(self):
        """Test postprocessing with scrape option."""
        gen = disposableHostGenerator()
        source = {"type": "html", "src": "https://example.com", "scrape": True}
        data = b"example.com\ntest.org"
        lines = ["example.com", "test.org"]
        result = gen._postprocess_data(source, data, lines)
        assert result == (2, 2)
        assert "example.com" in gen.scrape


class TestPostprocessDataExtended:
    """Extended tests for _postprocess_data method."""

    def test_postprocess_with_sha1_type(self):
        """Test postprocessing sha1 type adds to skip set."""
        gen = disposableHostGenerator()
        source = {"type": "sha1", "src": "hashes.txt"}
        # Use actual domain format that passes validation
        data = b"example.com\n"
        lines = ["example.com"]

        result = gen._postprocess_data(source, data, lines)

        assert result is True
        assert "example.com" in gen.skip

    def test_postprocess_no_valid_domains_logs_warning(self, caplog):
        """Test that warning is logged when no valid domains found."""
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        data = b"!!!invalid!!!\n@@@not_a_domain@@@"
        lines = ["!!!invalid!!!", "@@@not_a_domain@@@"]

        with caplog.at_level(logging.WARNING):
            result = gen._postprocess_data(source, data, lines)

        assert result is False
        assert "No results for source" in caplog.text


class TestProcessSource:
    """Tests for process method."""

    @patch.object(disposableHostGenerator, "_fetch_data")
    @patch.object(disposableHostGenerator, "_preprocess_data")
    @patch.object(disposableHostGenerator, "_postprocess_data")
    def test_process_success(self, mock_post, mock_pre, mock_fetch):
        """Test successful processing."""
        mock_fetch.return_value = b"data"
        mock_pre.return_value = ["example.com"]
        mock_post.return_value = (1, 1)
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        result = gen.process(source)
        assert result is True

    @patch.object(disposableHostGenerator, "_fetch_data")
    def test_process_fetch_none(self, mock_fetch):
        """Test processing when fetch returns None."""
        mock_fetch.return_value = None
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        result = gen.process(source)
        assert result is False

    @patch.object(disposableHostGenerator, "_fetch_data")
    @patch.object(disposableHostGenerator, "_preprocess_data")
    def test_process_preprocess_none(self, mock_pre, mock_fetch):
        """Test processing when preprocess returns None."""
        mock_fetch.return_value = b"data"
        mock_pre.return_value = None
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        result = gen.process(source)
        assert result is False


class TestScrapeRetryLogic:
    """Tests for scrape retry logic in process method."""

    @patch.object(disposableHostGenerator, "_fetch_data")
    @patch.object(disposableHostGenerator, "_preprocess_data")
    @patch.object(disposableHostGenerator, "_postprocess_data")
    def test_scrape_disabled_by_option(self, mock_post, mock_pre, mock_fetch):
        """Test skip_scrape option disables scraping."""
        mock_fetch.return_value = b"data"
        mock_pre.return_value = ["domain1.com"]
        mock_post.return_value = (1, 1)

        gen = disposableHostGenerator({"skip_scrape": True})
        source = {"type": "html", "src": "https://example.com", "scrape": True}
        result = gen.process(source)

        assert result is True
        # Verify scrape was disabled on the source
        assert source.get("scrape") is False

    @patch("disposablehosts.generator.time.sleep")
    @patch.object(disposableHostGenerator, "_fetch_data")
    @patch.object(disposableHostGenerator, "_preprocess_data")
    @patch.object(disposableHostGenerator, "_postprocess_data")
    def test_scrape_with_success(self, mock_post, mock_pre, mock_fetch, mock_sleep):
        """Test scrape with successful processing - exits loop by returning True (bool)."""
        mock_fetch.return_value = b"data"
        mock_pre.return_value = ["domain1.com"]

        # First call returns tuple (processed, found), second call returns True (bool) to exit loop
        mock_post.side_effect = [(1, 1), True]

        gen = disposableHostGenerator()
        source = {"type": "html", "src": "https://example.com", "scrape": True, "timeout": 0.01}
        result = gen.process(source)

        assert result is True
        assert mock_post.call_count >= 1

    @patch("disposablehosts.generator.time.sleep")
    @patch.object(disposableHostGenerator, "_fetch_data")
    @patch.object(disposableHostGenerator, "_preprocess_data")
    @patch.object(disposableHostGenerator, "_postprocess_data")
    def test_scrape_retry_exhaustion(self, mock_post, mock_pre, mock_fetch, mock_sleep):
        """Test scrape gives up after max retries."""
        mock_fetch.return_value = b"data"
        mock_pre.return_value = ["domain1.com"]

        # Return 0 processed for first 4 calls (exhausts scrape_max_retry=3), then success
        mock_post.side_effect = [
            (0, 1),  # First: retry=1
            (0, 1),  # Second: retry=2
            (0, 1),  # Third: retry=3
            (0, 1),  # Fourth: retry=4 > scrape_max_retry=3, returns True
        ]

        gen = disposableHostGenerator()
        source = {"type": "html", "src": "https://example.com", "scrape": True, "timeout": 0.001}
        result = gen.process(source)

        # Returns True when retry limit exceeded (scrape gives up)
        assert result is True
        assert mock_post.call_count == 4


class TestFallbackDomainExtraction:
    """Tests for DOMAIN_SEARCH_RE fallback in _postprocess_data."""

    def test_fallback_extraction_no_valid_domains(self):
        """Test fallback extraction when no valid domains found."""
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        # Raw data contains domains but not in a clean format
        data = b'<html>contact us at "example.com" or "test.org"</html>'
        lines = []  # No valid lines after initial processing

        result = gen._postprocess_data(source, data, lines)

        # Should extract domains from raw data using DOMAIN_SEARCH_RE
        assert result is not False
        assert "example.com" in gen.domains
        assert "test.org" in gen.domains

    def test_fallback_extraction_also_empty(self):
        """Test when both initial and fallback extraction return empty."""
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        data = b"<html>No valid domains here at all</html>"
        lines = []

        result = gen._postprocess_data(source, data, lines)

        assert result is False


class TestSourceHostnameArtifacts:
    """Tests for filtering hostname suffix artifacts from html sources.

    Regression test for https://github.com/disposable/disposable/issues/290:
    scrapes can emit trailing substrings of the source's own hostname
    (e.g. "fake.com", "ke.com", "e.com" from emailfake.com).
    """

    def test_html_source_drops_hostname_suffixes(self):
        """Proper suffixes of the source hostname are dropped; the hostname itself is kept."""
        gen = disposableHostGenerator()
        source = {"type": "html", "src": "https://emailfake.com", "scrape": True}
        data = b""
        lines = ["emailfake.com", "fake.com", "ilfake.com", "mailfake.com", "ke.com", "e.com", "realdomain.com"]

        result = gen._postprocess_data(source, data, lines)

        assert result is not False
        assert "emailfake.com" in gen.domains
        assert "realdomain.com" in gen.domains
        for artifact in ("fake.com", "ilfake.com", "mailfake.com", "ke.com", "e.com"):
            assert artifact not in gen.domains
            assert artifact not in gen.scrape

    def test_html_source_keeps_apex_domain(self):
        """Apex domain of a www.* source host is a legit self-reference, not an artifact."""
        gen = disposableHostGenerator()
        source = {"type": "html", "src": "https://www.fakemail.net/index/index", "regex": None}
        data = b""
        lines = ["fakemail.net", "www.fakemail.net", "mail.net", "realdomain.com"]

        result = gen._postprocess_data(source, data, lines)

        assert result is not False
        assert "fakemail.net" in gen.domains
        assert "realdomain.com" in gen.domains
        assert "mail.net" not in gen.domains

    def test_html_source_keeps_unrelated_suffixes(self):
        """Domains that are not suffixes of the source hostname are kept."""
        gen = disposableHostGenerator()
        source = {"type": "html", "src": "https://tempm.com", "scrape": True}
        data = b""
        lines = ["tempm.com", "someother.com", "mail.tempm.com"]

        result = gen._postprocess_data(source, data, lines)

        assert result is not False
        assert "tempm.com" in gen.domains
        assert "someother.com" in gen.domains
        assert "mail.tempm.com" in gen.domains

    def test_non_html_source_not_filtered(self):
        """List sources are unaffected by the hostname suffix filter."""
        gen = disposableHostGenerator()
        source = {"type": "list", "src": "https://example.com"}
        data = b""
        lines = ["ample.com", "example.com"]

        result = gen._postprocess_data(source, data, lines)

        assert result == (2, 2)
        assert "ample.com" in gen.domains


class TestCustomSources:
    """Tests for custom source processors."""

    @patch("disposablehosts.generator.httpx.post")
    def test_process_tempamail(self, mock_post):
        """Tempamail source creates a client then fetches the domain list."""
        gen = disposableHostGenerator()
        mock_post.side_effect = [
            type("R", (), {"json": lambda s: {"client": {"uuid": "u-1"}}})(),
            type("R", (), {"json": lambda s: {"domains": [{"name": "ogzmail.com"}, {"name": "ozvmail.com"}, {"tld": "com"}]}})(),
        ]
        assert gen._processTempamail() == ["ogzmail.com", "ozvmail.com"]
        assert mock_post.call_count == 2

    @patch("disposablehosts.generator.httpx.post")
    def test_process_tempamail_failure(self, mock_post):
        """Tempamail source returns None on request failure."""
        gen = disposableHostGenerator()
        mock_post.side_effect = Exception("boom")
        assert gen._processTempamail() is None

    @patch("disposablehosts.generator.httpx.get")
    def test_process_yydsmail(self, mock_get):
        """YYDSMail source reads the public domain pool from /v1/domains."""
        gen = disposableHostGenerator()
        mock_get.return_value = type(
            "R",
            (),
            {
                "json": lambda s: {
                    "success": True,
                    "data": [
                        {"domain": "yyds-mail-01.cc.cd", "isPublic": True},
                        {"domain": "xuicf1r.site", "isPublic": True},
                        {"domain": "owner-only.example", "isPublic": False},
                        {"isPublic": True},
                    ],
                }
            },
        )()
        assert gen._processYYDSMail() == ["yyds-mail-01.cc.cd", "xuicf1r.site"]

    @patch("disposablehosts.generator.httpx.get")
    def test_process_yydsmail_failure(self, mock_get):
        """YYDSMail source returns None on request failure."""
        gen = disposableHostGenerator()
        mock_get.side_effect = Exception("boom")
        assert gen._processYYDSMail() is None

    @patch("disposablehosts.generator.httpx.post")
    def test_process_ten_minutes_email(self, mock_post):
        """TenMinutesEmail source extracts the domain from the created inbox."""
        gen = disposableHostGenerator()
        mock_post.return_value = type("R", (), {"json": lambda s: {"email": "user@10minutes.email", "accessToken": "t"}})()
        assert gen._processTenMinutesEmail() == ["10minutes.email"]

    @patch("disposablehosts.generator.httpx.post")
    def test_process_ten_minutes_email_failure(self, mock_post):
        """TenMinutesEmail source returns None on request failure."""
        gen = disposableHostGenerator()
        mock_post.side_effect = Exception("boom")
        assert gen._processTenMinutesEmail() is None

    @patch("disposablehosts.generator.httpx.post")
    def test_process_emailnator(self, mock_post):
        """Emailnator source extracts the domain from the generated inbox."""
        gen = disposableHostGenerator()
        mock_post.return_value = type("R", (), {"json": lambda s: {"email": "abc@psnator.com", "status": "success"}})()
        assert gen._processEmailnator() == ["psnator.com"]

    @patch("disposablehosts.generator.httpx.post")
    def test_process_emailnator_failure(self, mock_post):
        """Emailnator source returns None on request failure."""
        gen = disposableHostGenerator()
        mock_post.side_effect = Exception("boom")
        assert gen._processEmailnator() is None

    @patch("disposablehosts.generator.httpx.post")
    def test_process_emailnator_error_response(self, mock_post):
        """Emailnator source returns None when the API reports an error."""
        gen = disposableHostGenerator()
        mock_post.return_value = type("R", (), {"json": lambda s: {"status": "error", "message": "Too many requests"}})()
        assert gen._processEmailnator() is None

    @patch("disposablehosts.generator.httpx.post")
    @patch("disposablehosts.generator.remoteData.fetch_http")
    def test_process_tempmailpro(self, mock_fetch, mock_post):
        """TempmailPro scans the bundle for domains and verifies via activate-session."""
        gen = disposableHostGenerator()

        def fetch(url, **kwargs):
            if url == "https://tempmailpro.io/":
                return b'<script src="/_next/static/chunks/a.js"></script>'
            return b"x = `${r}@tempmailpro.io` , generateRandomEmail , y = `${r}@tempmailpro.net`"

        mock_fetch.side_effect = fetch
        mock_post.return_value = type("R", (), {"json": lambda s: {"success": True}})()
        assert gen._processTempmailPro() == ["tempmailpro.io", "tempmailpro.net"]

    @patch("disposablehosts.generator.httpx.post")
    @patch("disposablehosts.generator.remoteData.fetch_http")
    def test_process_tempmailpro_forbidden(self, mock_fetch, mock_post):
        """TempmailPro returns None when every candidate is rejected."""
        gen = disposableHostGenerator()
        mock_fetch.return_value = b""
        mock_post.return_value = type("R", (), {"json": lambda s: {"error": "FORBIDDEN_DOMAIN"}})()
        assert gen._processTempmailPro() is None

    @patch("disposablehosts.generator.httpx.get")
    def test_process_tmp_al(self, mock_get):
        """TmpAl source authenticates anonymously and reads the domain pool."""
        gen = disposableHostGenerator()

        def get(url, **kwargs):
            if url.endswith("/api/auth"):
                return type("R", (), {"json": lambda s: {"access_token": "jwt"}})()
            return type("R", (), {"json": lambda s: ["mailapril.com", "MailOctober.com"]})()

        mock_get.side_effect = get
        assert gen._processTmpAl() == ["mailapril.com", "mailoctober.com"]

    @patch("disposablehosts.generator.httpx.get")
    def test_process_tmp_al_failure(self, mock_get):
        """TmpAl source returns None on request failure."""
        gen = disposableHostGenerator()
        mock_get.side_effect = Exception("boom")
        assert gen._processTmpAl() is None

    @patch("disposablehosts.generator.fetch_MX")
    def test_process_testinator_email(self, mock_mx):
        """TestinatorEmail emits the base domain while wildcard MX is live."""
        gen = disposableHostGenerator()
        mock_mx.return_value = ("testinator.email", True)
        assert gen._processTestinatorEmail() == ["testinator.email"]

    @patch("disposablehosts.generator.fetch_MX")
    def test_process_testinator_email_dead(self, mock_mx):
        """TestinatorEmail returns None once the wildcard MX is gone."""
        gen = disposableHostGenerator()
        mock_mx.return_value = ("testinator.email", False)
        assert gen._processTestinatorEmail() is None

    @patch("disposablehosts.generator.httpx.get")
    def test_process_boomlify(self, mock_get):
        """Boomlify source reads active domains from the public pool API."""
        gen = disposableHostGenerator()
        mock_get.return_value = type(
            "R",
            (),
            {
                "json": lambda s: [
                    {"domain": "Kuromee.com", "is_active": 1},
                    {"domain": "zikzak.site", "is_active": 1},
                    {"domain": "rotated.example", "is_active": 0},
                    {"domain": 42, "is_active": 1},
                    {"is_active": 1},
                ]
            },
        )()
        assert gen._processBoomlify() == ["kuromee.com", "zikzak.site"]

    @patch("disposablehosts.generator.httpx.get")
    def test_process_boomlify_failure(self, mock_get):
        """Boomlify source returns None on request failure or bad payload."""
        gen = disposableHostGenerator()
        mock_get.side_effect = Exception("boom")
        assert gen._processBoomlify() is None
        mock_get.side_effect = None
        mock_get.return_value = type("R", (), {"json": lambda s: {"error": "x"}})()
        assert gen._processBoomlify() is None

    @patch("disposablehosts.generator.httpx.post")
    def test_process_fiveminmail(self, mock_post):
        """FiveMinMail source extracts the domain from a generated address."""
        gen = disposableHostGenerator()
        mock_post.return_value = type("R", (), {"json": lambda s: {"email": "u_abc@Zelnro.com"}})()
        assert gen._processFiveMinMail() == ["zelnro.com"]

    @patch("disposablehosts.generator.httpx.post")
    def test_process_fiveminmail_failure(self, mock_post):
        """FiveMinMail source returns None on failure or missing email."""
        gen = disposableHostGenerator()
        mock_post.side_effect = Exception("boom")
        assert gen._processFiveMinMail() is None
        mock_post.side_effect = None
        mock_post.return_value = type("R", (), {"json": lambda s: {"detail": "rate limit"}})()
        assert gen._processFiveMinMail() is None

    @patch("disposablehosts.generator.httpx.post")
    def test_process_mailper(self, mock_post):
        """Mailper source reads domains from the GraphQL publicDomains query."""
        gen = disposableHostGenerator()
        mock_post.return_value = type(
            "R",
            (),
            {"json": lambda s: {"data": {"publicDomains": [{"domain": "Mailper.com"}, {"domain": "foo.bar"}, {"nodomain": 1}]}}},
        )()
        assert gen._processMailper() == ["foo.bar", "mailper.com"]

    @patch("disposablehosts.generator.httpx.post")
    def test_process_mailper_failure(self, mock_post):
        """Mailper source returns None on failure or empty pool."""
        gen = disposableHostGenerator()
        mock_post.side_effect = Exception("boom")
        assert gen._processMailper() is None
        mock_post.side_effect = None
        mock_post.return_value = type("R", (), {"json": lambda s: {"data": {"publicDomains": []}}})()
        assert gen._processMailper() is None

    @patch("disposablehosts.generator.httpx.get")
    @patch("disposablehosts.generator.remoteData.fetch_http")
    def test_process_fakemail_generator(self, mock_fetch, mock_get):
        """Fake Mail Generator sites read the pool from /api/domains.php."""
        gen = disposableHostGenerator()
        mock_fetch.return_value = b'<html><meta name="api-token" content="tok123"></html>'
        mock_get.return_value = type(
            "R",
            (),
            {
                "json": lambda s: [
                    {"ascii": "skytopway.com", "display": "skytopway.com", "idn": False, "wc": ""},
                    {"ascii": "zzzz.rey678.shop", "display": "", "idn": False, "wc": "rey678.shop"},
                    {"ascii": "", "wc": ""},
                    "not-a-dict",
                ]
            },
        )()
        assert gen._processEmailfake() == ["rey678.shop", "skytopway.com", "zzzz.rey678.shop"]
        mock_get.assert_called_once()
        assert mock_get.call_args[0][0] == "https://emailfake.com/api/domains.php"
        assert mock_get.call_args[1]["headers"]["X-API-Token"] == "tok123"

    @patch("disposablehosts.generator.remoteData.fetch_http")
    def test_process_fakemail_generator_no_token(self, mock_fetch):
        """Fake Mail Generator sites return None when the api-token is absent."""
        gen = disposableHostGenerator()
        mock_fetch.return_value = b"<html>no token here</html>"
        assert gen._processTempm() is None

    @patch("disposablehosts.generator.httpx.get")
    @patch("disposablehosts.generator.remoteData.fetch_http")
    def test_process_fakemail_generator_failure(self, mock_fetch, mock_get):
        """Fake Mail Generator sites return None on request failure."""
        gen = disposableHostGenerator()
        mock_fetch.return_value = b'<meta name="api-token" content="t">'
        mock_get.side_effect = Exception("boom")
        assert gen._processMailTemp() is None

    @patch("disposablehosts.generator.httpx.post")
    def test_process_dustmail(self, mock_post, monkeypatch):
        """Dustmail source reads meta.available_domains via API key."""
        monkeypatch.setenv("DUSTMAIL_API_KEY", "dm_live_test")
        gen = disposableHostGenerator()
        mock_post.return_value = type("R", (), {"json": lambda s: {"meta": {"available_domains": ["dustmail.net", "x.example"]}}})()
        assert gen._processDustmail() == ["dustmail.net", "x.example"]

    def test_dustmail_source_requires_api_key(self, monkeypatch):
        """Dustmail source is only registered when DUSTMAIL_API_KEY is set."""
        monkeypatch.delenv("DUSTMAIL_API_KEY", raising=False)
        gen = disposableHostGenerator()
        assert not any(s.get("src") == "Dustmail" for s in gen.sources)
        monkeypatch.setenv("DUSTMAIL_API_KEY", "dm_live_test")
        gen2 = disposableHostGenerator()
        assert any(s.get("src") == "Dustmail" for s in gen2.sources)
