"""Dynamic integration tests for disposable email sources.

These tests verify that each configured source can be fetched and parsed correctly.
Tests are generated dynamically from the sources defined in the generator.
"""

import json
import logging
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

import pytest

# Add src to path
sys.path.insert(0, "src")

from disposablehosts.constants import DOMAIN_RE, DOMAIN_SEARCH_RE, HTML_GENERIC_RE, SHA1_RE
from disposablehosts.generator import disposableHostGenerator
from disposablehosts.remote_data import remoteData

# Configure logging
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Suppress noisy loggers
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("tldextract").setLevel(logging.WARNING)


def check_valid_domain(host: str) -> bool:
    """Check if the given host is a valid domain name."""
    try:
        if not DOMAIN_RE.match(host):
            return False
        parts = host.split(".")
        return len(parts) >= 2 and all(len(p) > 0 for p in parts)
    except Exception:
        return False


def preprocess_file_data(data: bytes, encoding: str = "utf-8") -> List[str]:
    """Preprocess file data - filter comments and empty lines."""
    lines = []
    for line in data.splitlines():
        try:
            line_str = line.decode(encoding).strip()
            if line_str.startswith("#") or line_str == "":
                continue
            lines.append(line_str)
        except UnicodeDecodeError:
            continue
    return lines


def preprocess_json_data(data: bytes, encoding: str = "utf-8") -> Optional[List[str]]:
    """Preprocess JSON data - extract domains from various API formats."""
    raw = {}
    try:
        raw = json.loads(data.decode(encoding))
    except Exception as e:
        if "Unexpected UTF-8 BOM" in str(e):
            raw = json.loads(data.decode("utf-8-sig"))
        else:
            return None

    if not raw:
        return None

    if "domains" in raw:
        raw = raw["domains"]

    if "email" in raw:
        s = re.search(r"^.+?@?([a-z0-9\.-]{1,128})$", raw["email"])
        if s:
            raw = [s[1]]

    if not isinstance(raw, list):
        return None
    return [str(line) for line in raw if line and isinstance(line, str)]


def preprocess_html_data(data: bytes, regex: Optional[Any] = None, encoding: str = "utf-8") -> List[str]:
    """Preprocess HTML data - extract domains using regex patterns."""
    import html

    raw = data.decode(encoding)
    html_re = regex if regex is not None else HTML_GENERIC_RE
    if not isinstance(html_re, list):
        html_re = [html_re]

    html_ipt = raw
    html_list = []
    for html_re_item in html_re:
        html_list = html_re_item.findall(html_ipt)
        html_ipt = "\n".join([o[0] if isinstance(o, tuple) else o for o in html_list])

    return [html.unescape(opt[0]) if isinstance(opt, tuple) else html.unescape(opt) for opt in html_list]


def preprocess_sha1_data(data: bytes) -> List[str]:
    """Preprocess SHA1 data - extract valid SHA1 hashes."""
    sha1_list = []
    for sha1_str in [line.decode("ascii", errors="ignore").lower() for line in data.splitlines()]:
        if not sha1_str or not SHA1_RE.match(sha1_str):
            continue
        sha1_list.append(sha1_str)
    return sha1_list


def verify_source(source: Dict[str, Any]) -> Tuple[bool, str, int]:
    """Verify a single source and return (success, message, domain_count)."""
    try:
        src_type = source.get("type", "list")
        src_url = source.get("src", "")

        if not src_url:
            return False, "No source URL", 0

        if src_type == "file":
            # File sources are optional and verified separately
            return True, "File source (verified separately)", 0

        if src_type == "whitelist":
            # Whitelist sources are handled differently
            return True, "Whitelist source (verified separately)", 0

        if src_type == "greylist":
            # Greylist is a remote list (like 'list' type)
            pass  # Fall through to HTTP fetching

        if src_type == "greylist_file":
            return True, "Greylist file source (verified separately)", 0

        if src_type == "whitelist_file":
            return True, "Whitelist file source (verified separately)", 0

        if src_type == "ws":
            data = remoteData.fetch_ws(src_url)
            if not data:
                return False, "WebSocket connection failed", 0
            # WebSocket data parsing would go here
            return True, "WebSocket connected", 0

        # HTTP-based sources
        headers = {}
        if src_type == "json":
            headers["Accept"] = "application/json, text/javascript, */*; q=0.01"
            headers["X-Requested-With"] = "XMLHttpRequest"

        res = remoteData.fetch_http_raw(src_url, headers=headers, timeout=15)
        if res is None:
            return False, "HTTP request failed (no response)", 0

        if res.status_code >= 400:
            return False, f"HTTP {res.status_code}", 0

        data = res.read()
        if not data:
            return False, "Empty response", 0

        encoding = source.get("encoding", "utf-8")

        if src_type == "json":
            lines = preprocess_json_data(data, encoding)
        elif src_type == "html":
            lines = preprocess_html_data(data, source.get("regex"), encoding)
        elif src_type in ("list", "greylist"):
            # Both 'list' and 'greylist' are plain text lists
            lines = preprocess_file_data(data, encoding)
        elif src_type == "sha1":
            lines = preprocess_sha1_data(data)
        else:
            return False, f"Unknown type: {src_type}", 0

        if lines is None:
            return False, "Failed to parse data", 0

        if src_type == "sha1":
            return len(lines) > 0, f"SHA1 list returned {len(lines)} hashes", len(lines)

        domains = [line.lower().strip(" .,;@") for line in lines if isinstance(line, str)]
        domains = [d for d in domains if check_valid_domain(d)]

        if not domains:
            # Try fallback regex search
            fallback = [match.lower().strip(" .,;@") for match in DOMAIN_SEARCH_RE.findall(str(data))]
            domains = [d for d in fallback if check_valid_domain(d)]

        return len(domains) > 0, f"Returned {len(domains)} valid domains", len(domains)

    except Exception as e:
        return False, f"Exception: {e}", 0


def get_test_sources():
    """Get list of sources to test from the generator."""
    # Create a generator instance to get the sources list
    gen = disposableHostGenerator(options={"verbose": False})
    return gen.sources


def pytest_generate_tests(metafunc):
    """Dynamically generate test cases for each source."""
    if "source" in metafunc.fixturenames:
        sources = get_test_sources()
        # Filter out file sources that don't need network testing
        test_sources = [s for s in sources if s.get("type") not in ("file", "whitelist", "whitelist_file")]
        # Create test IDs from source URLs
        test_ids = []
        for s in test_sources:
            src = s.get("src", "unknown")
            # Create a short identifier from the URL
            if "/" in src:
                name = src.split("/")[-1][:30] if src.split("/")[-1] else src.split("/")[-2][:30]
            else:
                name = src[:30]
            test_ids.append(name)
        metafunc.parametrize("source", test_sources, ids=test_ids)


@pytest.mark.integration
@pytest.mark.network
class TestSources:
    """Integration tests for disposable email sources."""

    def test_source_reachable_and_parsable(self, source):
        """Test that a source is reachable and returns parseable data."""
        src_url = source.get("src", "")
        src_type = source.get("type", "list")

        # Skip file-based sources
        if src_type in ("file", "whitelist", "whitelist_file"):
            pytest.skip("File-based sources are tested separately")

        success, message, count = verify_source(source)

        if not success:
            pytest.fail(f"Source failed: {src_url}\nReason: {message}")

        # Assert that we got some data
        assert count > 0, f"Source returned no valid data: {message}"
