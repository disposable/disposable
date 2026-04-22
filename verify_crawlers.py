#!/usr/bin/env python3
"""Verify which crawlers in disposablehosts are still working.

This script uses the new modular disposablehosts package to verify
that each source can still be fetched and parsed correctly.

Usage:
    python verify_crawlers.py          # Verify all sources
    python verify_crawlers.py --json   # Output JSON report
"""

import argparse
import sys
import json
import re
import html
import logging
from typing import Any, Dict, List, Optional, Tuple

# Add src to path for importing the package
sys.path.insert(0, "src")

from disposablehosts.remote_data import remoteData
from disposablehosts.constants import (
    DOMAIN_RE,
    DOMAIN_SEARCH_RE,
    HTML_GENERIC_RE,
    SHA1_RE,
    generate_random_string,
)

# Suppress warnings
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Disable httpx logging
httpx_logger = logging.getLogger("httpx")
httpx_logger.setLevel("WARNING")


# All sources from disposablehosts/generator.py (synced)
sources = [
    {"name": "gist_adamloving", "type": "list", "src": "https://gist.githubusercontent.com/adamloving/4401361/raw/"},
    {"name": "gist_jamesonev", "type": "list", "src": "https://gist.githubusercontent.com/jamesonev/7e188c35fd5ca754c970e3a1caf045ef/raw/"},
    {
        "name": "static_disposable_mail_data",
        "type": "list",
        "src": "https://raw.githubusercontent.com/disposable/static-disposable-lists/master/mail-data-hosts-net.txt",
    },
    {"name": "wesbos_burner", "type": "list", "src": "https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt"},
    {"name": "static_disposable_manual", "type": "list", "src": "https://raw.githubusercontent.com/disposable/static-disposable-lists/master/manual.txt"},
    {
        "name": "martenson_disposable",
        "type": "list",
        "src": "https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable_email_blocklist.conf",
    },
    {"name": "daisy1754_jp", "type": "list", "src": "https://raw.githubusercontent.com/daisy1754/jp-disposable-emails/master/list.txt"},
    {"name": "fgribreau_mailchecker", "type": "list", "src": "https://raw.githubusercontent.com/FGRibreau/mailchecker/master/list.txt"},
    {"name": "7c_fakefilter", "type": "list", "src": "https://raw.githubusercontent.com/7c/fakefilter/main/txt/data.txt"},
    {"name": "flotwig_disposable", "type": "list", "src": "https://raw.githubusercontent.com/flotwig/disposable-email-addresses/master/domains.txt"},
    {
        "name": "geroldsetz_mailinator",
        "type": "sha1",
        "src": "https://raw.githubusercontent.com/GeroldSetz/Mailinator-Domains/master/mailinator_domains_from_bdea.cc.txt",
    },
    {
        "name": "geroldsetz_emailondeck",
        "type": "list",
        "src": "https://raw.githubusercontent.com/GeroldSetz/emailondeck.com-domains/refs/heads/master/emailondeck.com_domains_from_bdea.cc.txt",
    },
    {"name": "inboxes_api", "type": "json", "src": "https://inboxes.com/api/v2/domain"},
    {"name": "tempmail_io_api", "type": "json", "src": "https://api.internal.temp-mail.io/api/v2/domains"},
    # fakemail.net - working again (HTTP 200)
    {"name": "fakemail_net", "type": "html", "src": "https://www.fakemail.net/index/index", "regex": DOMAIN_SEARCH_RE},
    # mailpoof.com - DNS NXDOMAIN, service permanently offline
    # {'name': 'mailpoof', 'type': 'json', 'src': 'https://api.mailpoof.com/domains'},
    # dropmail.me - WebSocket URL changed to /api/graphql/<token>/websocket, needs new implementation
    # {'name': 'dropmail_ws', 'type': 'ws', 'src': 'wss://dropmail.me/websocket'},
    # tempmail.ninja - requires cloudflare bypass (TODO: implement workaround)
    # {'name': 'tempmail_ninja', 'type': 'html', 'src': 'https://tempmail.ninja/en'},
    # tmp.al - luxusmail.org redirects here (HTTP 301), now an Android app
    # {'name': 'tmp_al', 'type': 'html', 'src': 'https://tmp.al',
    #     'regex': re.compile(r"""<a.+?domain-selector\"[^>]+>@([a-z0-9\.-]{1,128})""", re.I)},
    # tempmailo.com - cloudflare challenge, can't scrape
    # {'name': 'tempmailo', 'type': 'custom', 'src': 'Tempmailo', 'scrape': True},
    # correotemporal.org - redirects to tempmail.ninja (HTTP 301)
    # {'name': 'correotemporal', 'type': 'html', 'src': 'https://correotemporal.org', 'regex': DOMAIN_SEARCH_RE},
    {"name": "blacklist", "type": "file", "src": "blacklist.txt", "ignore_not_exists": True},
    {
        "name": "rotvpn_disposable",
        "type": "html",
        "src": "https://www.rotvpn.com/en/disposable-email",
        "regex": [
            re.compile(r"""<div class=\"container text-center\">\s+<div[^>]+>(.+?)</div>\s+</div>""", re.I | re.DOTALL),
            DOMAIN_SEARCH_RE,
        ],
    },
    {
        "name": "emailfake_com",
        "type": "html",
        "src": "https://emailfake.com",
        "regex": re.compile(r"""change_dropdown_list[^"]+"[^>]+>@?([a-z0-9\.-]{1,128})""", re.I),
        "scrape": True,
    },
    {
        "name": "email-fake_com",
        "type": "html",
        "src": "https://email-fake.com",
        "regex": re.compile(r"""change_dropdown_list[^"]+"[^>]+>@?([a-z0-9\.-]{1,128})""", re.I),
        "scrape": True,
    },
    {
        "name": "tempm_com",
        "type": "html",
        "src": "https://tempm.com",
        "regex": re.compile(r"""change_dropdown_list[^"]+"[^>]+>@?([a-z0-9\.-]{1,128})""", re.I),
        "scrape": True,
    },
    {
        "name": "mail-fake_com",
        "type": "html",
        "src": "https://mail-fake.com",
        "regex": re.compile(r"""change_dropdown_list[^"]+"[^>]+>@?([a-z0-9\.-]{1,128})""", re.I),
        "scrape": True,
    },
    {
        "name": "generator_email",
        "type": "html",
        "src": "https://generator.email",
        "regex": re.compile(r"""change_dropdown_list[^"]+"[^>]+>@?([a-z0-9\.-]{1,128})""", re.I),
        "scrape": True,
    },
    {"name": "guerrillamail", "type": "html", "src": "https://www.guerrillamail.com/en/"},
    {"name": "trash-mail", "type": "html", "src": "https://www.trash-mail.com/inbox/"},
    {
        "name": "mail-temp_com",
        "type": "html",
        "src": "https://mail-temp.com",
        "regex": re.compile(r"""change_dropdown_list[^"]+"[^>]+>@?([a-z0-9\.-]{1,128})""", re.I),
        "scrape": True,
    },
    {
        "name": "temporary-mail_net",
        "type": "html",
        "src": "https://www.temporary-mail.net",
        "regex": re.compile(r"""<a.+?data-mailhost=\"@?([a-z0-9\.-]{1,128})\"""", re.I),
    },
    {
        "name": "nospam_today",
        "type": "html",
        "src": "https://nospam.today",
        "regex": [
            re.compile(r"""wire:initial-data="(.+?domains[^\"]+)\""""),
            re.compile(r"""\&quot;domains\&quot;:\[([^\]]+)\]"""),
            re.compile(r"""\&quot;([^\&]+)\&quot;"""),
        ],
    },
    {"name": "lortemail_dk", "type": "html", "src": "https://lortemail.dk"},
    {
        "name": "tempmail_plus",
        "type": "html",
        "src": "https://tempmail.plus/en/",
        "regex": re.compile(r"""<button type=\"button\" class=\"dropdown-item\">([^<]+)</button>""", re.I),
    },
    {
        "name": "spamok_nl",
        "type": "html",
        "src": "https://spamok.nl/demo" + generate_random_string(8),
        "regex": re.compile(r"""<option\s+value="([^"]+)">""", re.I),
    },
    {
        "name": "tempr_email",
        "type": "html",
        "src": "https://tempr.email",
        "regex": re.compile(r"""<option\s+value[^>]*>@?([a-z\-\.\&#;\d+]+)\s*(\(PW\))?<\/option>""", re.I),
    },
    {
        "name": "yopmail",
        "type": "html",
        "src": "https://yopmail.com/domain?d=all",
        "regex": [
            re.compile(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", re.I),
        ],
    },
]


def check_valid_domains(host: str) -> bool:
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


def preprocess_websocket_data(data: bytes) -> List[str]:
    """Preprocess WebSocket data - extract domains from dropmail format."""
    for line in data.splitlines():
        try:
            line_str = line.decode("utf-8")
            if line_str.startswith("D"):
                return line_str[1:].split(",")
        except UnicodeDecodeError:
            continue
    return []


def verify_source(source: Dict[str, Any]) -> Tuple[bool, str, int]:
    """Verify a single source and return (success, message, domain_count)."""
    try:
        src_type = source["type"]
        src_url = source["src"]
        name = source.get("name", src_url)

        if src_type == "file":
            # File sources are optional and verified separately
            return True, f"File source '{name}' (verified separately)", 0

        if src_type == "ws":
            data = remoteData.fetch_ws(src_url)
            if not data:
                return False, "WebSocket connection failed", 0
            domains = preprocess_websocket_data(data)
            valid_domains = [d for d in domains if check_valid_domains(d.lower().strip(" .,;@"))]
            return len(valid_domains) > 0, f"WS returned {len(valid_domains)} domains", len(valid_domains)

        # HTTP-based sources
        headers = {}
        if src_type == "json":
            headers["Accept"] = "application/json, text/javascript, */*; q=0.01"
            headers["X-Requested-With"] = "XMLHttpRequest"

        res = remoteData.fetch_http_raw(src_url, headers=headers, timeout=15)  # nosec B113
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
        elif src_type == "list":
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
        domains = [d for d in domains if check_valid_domains(d)]

        if not domains:
            # Try fallback regex search
            fallback = [match.lower().strip(" .,;@") for match in DOMAIN_SEARCH_RE.findall(str(data))]
            domains = [d for d in fallback if check_valid_domains(d)]

        return len(domains) > 0, f"Returned {len(domains)} valid domains", len(domains)

    except Exception as e:
        return False, f"Exception: {e}", 0


def main():
    parser = argparse.ArgumentParser(description="Verify disposable email crawlers")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--source", "-s", help="Test only specific source by name")
    args = parser.parse_args()

    # Filter sources if specified
    test_sources = sources
    if args.source:
        test_sources = [s for s in sources if args.source.lower() in s.get("name", "").lower()]
        if not test_sources:
            print(f"No source found matching: {args.source}")
            sys.exit(1)

    if not args.json:
        print("=" * 80)
        print("DISPOSABLE EMAIL CRAWLER VERIFICATION")
        print("=" * 80)
        print()

    working = []
    broken = []
    results = []

    for i, source in enumerate(test_sources, 1):
        name = source.get("name", source["src"])
        url_display = source["src"][:70] + "..." if len(source["src"]) > 70 else source["src"]

        if not args.json:
            print(f"[{i}/{len(test_sources)}] Testing: {name}")
            print(f"      URL: {url_display}")

        success, msg, count = verify_source(source)

        result = {
            "name": name,
            "url": source["src"],
            "success": success,
            "message": msg,
            "count": count,
        }
        results.append(result)

        if success:
            if not args.json:
                print(f"      Status: {'WORKING' if count > 0 else 'WORKING (no new domains)'}")
                print(f"      Result: {msg}")
            working.append((name, msg))
        else:
            if not args.json:
                print(f"      Status: ** BROKEN **")
                print(f"      Reason: {msg}")
            broken.append((name, msg))

        if not args.json:
            print()

    if args.json:
        print(
            json.dumps(
                {
                    "summary": {
                        "total": len(test_sources),
                        "working": len(working),
                        "broken": len(broken),
                    },
                    "results": results,
                },
                indent=2,
            )
        )
    else:
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"\nWORKING ({len(working)}):")
        for name, msg in working:
            print(f"  [OK] {name}: {msg}")

        print(f"\nBROKEN ({len(broken)}):")
        for name, msg in broken:
            print(f"  [FAIL] {name}: {msg}")

        print(f"\nTotal: {len(working)} working, {len(broken)} broken out of {len(test_sources)} crawlers")

    # Exit with error code if any broken sources
    sys.exit(0 if not broken else 1)


if __name__ == "__main__":
    main()
