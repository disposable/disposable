#!/usr/bin/env python3
"""Verify which crawlers in disposable.py are still working."""

import json
import re
import html
import logging
import httpx
import time
import string
import random
from typing import Any, Dict, List, Optional, Tuple
from websocket import create_connection

# Suppress warnings
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Disable httpx logging
httpx_logger = logging.getLogger("httpx")
httpx_logger.setLevel("WARNING")

DOMAIN_RE = re.compile(r"^[a-z\d-]{1,63}(\.[a-z-\.]{2,63})+$")
DOMAIN_SEARCH_RE = re.compile(r'["\'\s>]([a-z\d\.-]{1,63}\.[a-z\-]{2,63})["\'\s<]', re.I)
HTML_GENERIC_RE = re.compile(r"""<option[^>]*>@?([a-z\-\.\&#;\d+]+)\s*(\(PW\))?<\/option>""", re.I)
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}")
RETRY_ERRORS_RE = re.compile(r"""(The read operation timed out|urlopen error timed out)""", re.I)


def generate_random_string(length: int) -> str:
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for _ in range(length))


class remoteData:
    @staticmethod
    def fetch_ws(src: str) -> bytes:
        try:
            ws = create_connection(src, timeout=10)
            data = []
            for _ in range(3):
                line = ws.recv()
                if type(line) is str:
                    line = line.encode("utf-8")
                data.append(line)
            ws.close()
            return b"\n".join(data)
        except Exception as e:
            logger.warning(f"WebSocket connection failed: {e}")
            return b""

    @staticmethod
    def fetch_http_raw(
        url: str, headers: Optional[Dict[str, str]] = None, timeout: Optional[int] = None, max_retry: Optional[int] = None
    ) -> Optional[httpx.Response]:
        if not headers:
            headers = {}
        if timeout is None:
            timeout = 10
        if max_retry is None:
            max_retry = 3

        retry = 0
        headers.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/118.0")
        headers.setdefault("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

        with httpx.Client(http2=True, verify=False, follow_redirects=True) as client:
            while retry < max_retry:
                try:
                    return client.get(url, headers=headers, timeout=timeout)
                except Exception as e:
                    retry += 1
                    if RETRY_ERRORS_RE.search(str(e)) and retry < max_retry:
                        time.sleep(1)
                        continue
                    logger.warning(f"Fetching URL {url} failed: {e}")
                    break
        return None

    @staticmethod
    def fetch_http(url: str, headers: Optional[Dict[str, str]] = None, timeout: Optional[int] = None, max_retry: Optional[int] = None) -> bytes:
        res = remoteData.fetch_http_raw(url, headers, timeout, max_retry)
        return (res and res.read()) or b""


# All sources from disposable.py (lines 170-244)
sources = [
    {"name": "gist_adamloving", "type": "list", "external": True, "src": "https://gist.githubusercontent.com/adamloving/4401361/raw/"},
    {"name": "gist_jamesonev", "type": "list", "external": True, "src": "https://gist.githubusercontent.com/jamesonev/7e188c35fd5ca754c970e3a1caf045ef/raw/"},
    {
        "name": "static_disposable_mail_data",
        "type": "list",
        "external": False,
        "src": "https://raw.githubusercontent.com/disposable/static-disposable-lists/master/mail-data-hosts-net.txt",
    },
    {"name": "wesbos_burner", "type": "list", "external": True, "src": "https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt"},
    {
        "name": "static_disposable_manual",
        "type": "list",
        "external": False,
        "src": "https://raw.githubusercontent.com/disposable/static-disposable-lists/master/manual.txt",
    },
    {
        "name": "martenson_disposable",
        "type": "list",
        "external": True,
        "src": "https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable_email_blocklist.conf",
    },
    {"name": "daisy1754_jp", "type": "list", "external": True, "src": "https://raw.githubusercontent.com/daisy1754/jp-disposable-emails/master/list.txt"},
    {"name": "fgribreau_mailchecker", "type": "list", "external": True, "src": "https://raw.githubusercontent.com/FGRibreau/mailchecker/master/list.txt"},
    {"name": "7c_fakefilter", "type": "list", "external": True, "src": "https://raw.githubusercontent.com/7c/fakefilter/main/txt/data.txt"},
    {
        "name": "flotwig_disposable",
        "type": "list",
        "external": True,
        "src": "https://raw.githubusercontent.com/flotwig/disposable-email-addresses/master/domains.txt",
    },
    {
        "name": "geroldsetz_mailinator",
        "type": "sha1",
        "external": True,
        "src": "https://raw.githubusercontent.com/GeroldSetz/Mailinator-Domains/master/mailinator_domains_from_bdea.cc.txt",
    },
    {
        "name": "geroldsetz_emailondeck",
        "type": "list",
        "external": True,
        "src": "https://raw.githubusercontent.com/GeroldSetz/emailondeck.com-domains/refs/heads/master/emailondeck.com_domains_from_bdea.cc.txt",
    },
    {"name": "inboxes_api", "type": "json", "src": "https://inboxes.com/api/v2/domain"},
    {"name": "tempmail_io_api", "type": "json", "src": "https://api.internal.temp-mail.io/api/v2/domains"},
    {"name": "fakemail_net", "type": "json", "src": "https://www.fakemail.net/index/index", "scrape": True},
    {
        "name": "rotvpn_disposable",
        "type": "html",
        "src": "https://www.rotvpn.com/en/disposable-email",
        "regex": [re.compile(r"""<div class=\"container text-center\">\s+<div[^>]+>(.+?)</div>\s+</div>""", re.I | re.DOTALL), DOMAIN_SEARCH_RE],
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
    {"name": "correotemporal", "type": "html", "src": "https://correotemporal.org", "regex": DOMAIN_SEARCH_RE},
    {
        "name": "temporary-mail_net",
        "type": "html",
        "src": "https://www.temporary-mail.net",
        "regex": re.compile(r"""<a.+?data-mailhost=\"@?([a-z0-9\.-]{1,128})\"""", re.I),
    },
    {
        "name": "nospam_today",
        "type": "html",
        "src": "https://nospam.today/home",
        "regex": [
            re.compile(r"""wire:initial-data="(.+?domains[^\"]+)\""""),
            re.compile(r"""\&quot;domains\&quot;:\[([^\]]+)\]"""),
            re.compile(r"""\&quot;([^\&]+)\&quot;"""),
        ],
    },
    {
        "name": "luxusmail",
        "type": "html",
        "src": "https://www.luxusmail.org",
        "regex": re.compile(r"""<a.+?domain-selector\"[^>]+>@([a-z0-9\.-]{1,128})""", re.I),
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
    {"name": "dropmail_ws", "type": "ws", "src": "wss://dropmail.me/websocket"},
    {"name": "tempmailo", "type": "custom", "src": "Tempmailo", "scrape": True},
    {"name": "yopmail", "type": "html", "src": "https://yopmail.com/domain?d=all", "regex": [re.compile(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", re.I)]},
]


def check_valid_domains(host: str) -> bool:
    try:
        if not DOMAIN_RE.match(host):
            return False
        parts = host.split(".")
        return len(parts) >= 2 and all(len(p) > 0 for p in parts)
    except Exception:
        return False


def preprocess_json(source: Dict[str, Any], data: bytes) -> Optional[List[str]]:
    raw = {}
    try:
        raw = json.loads(data.decode(source.get("encoding", "utf-8")))
    except Exception as e:
        if "Unexpected UTF-8 BOM" in str(e):
            raw = json.loads(data.decode("utf-8-sig"))

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
    return list(filter(lambda line: line and isinstance(line, str), raw))


def preprocess_file(source: Dict[str, Any], data: bytes) -> List[str]:
    lines = []
    for line in data.splitlines():
        line = line.decode(source.get("encoding", "utf-8")).strip()
        if line.startswith("#") or line == "":
            continue
        lines.append(line)
    return lines


def preprocess_html(source: Dict[str, Any], data: bytes) -> List[str]:
    raw = data.decode(source.get("encoding", "utf-8"))
    html_re = source.get("regex", HTML_GENERIC_RE)
    if type(html_re) is not list:
        html_re = [
            html_re,
        ]

    html_ipt = raw
    html_list = []
    for html_re_item in html_re:
        html_list = html_re_item.findall(html_ipt)
        html_ipt = "\n".join(list(map(lambda o: o[0] if type(o) is tuple else o, html_list)))

    return list(map(lambda opt: html.unescape(opt[0]) if type(opt) is tuple else opt, html_list))


def preprocess_sha1(data: bytes) -> List[str]:
    sha1_list = []
    for sha1_str in [line.decode("ascii").lower() for line in data.splitlines()]:
        if not sha1_str or not SHA1_RE.match(sha1_str):
            continue
        sha1_list.append(sha1_str)
    return sha1_list


def process_tempmailo() -> Optional[List[str]]:
    res = remoteData.fetch_http_raw("https://tempmailo.com/")
    if res is None:
        return None

    cookies = {}
    for ky, vl in res.headers.items():
        if ky.lower() != "set-cookie":
            continue
        try:
            (ck_name, ck_data) = vl.split("=", 1)
            if ck_name.startswith("__"):
                continue
            (ck_value, _) = ck_data.split(";", 1)
            cookies[ck_name] = ck_value
        except ValueError:
            continue

    body = res.read().decode("utf8")

    f = re.search('name="__RequestVerificationToken".+?value="([^"]+)"', body)
    if not f:
        return None

    headers = {
        "requestverificationtoken": f[1],
        "accept": "application/json, text/plain, */*",
        "x-requested-with": "XMLHttpRequest",
        "referer": "https://tempmailo.com/",
        "cookie": "; ".join([f"{ky}={vl}" for ky, vl in cookies.items()]),
    }

    data = remoteData.fetch_http("https://tempmailo.com/changemail", headers=headers)
    if not data:
        return None

    lines = []
    for line in data.splitlines():
        try:
            (_, domain) = line.decode("utf8").split("@", 1)
            lines.append(domain)
        except ValueError:
            continue
    return lines


def verify_source(source: Dict[str, Any]) -> Tuple[bool, str, int]:
    """Verify a single source and return (success, message, domain_count)."""
    try:
        src_type = source["type"]
        src_url = source["src"]

        if src_type == "custom":
            if source["src"] == "Tempmailo":
                lines = process_tempmailo()
                if lines is None:
                    return False, "Failed to fetch/parse", 0
                domains = list(filter(check_valid_domains, [line.lower().strip(" .,;@") for line in lines]))
                return len(domains) > 0, f"Custom crawler returned {len(domains)} domains", len(domains)
            return False, "Unknown custom crawler", 0

        if src_type == "ws":
            data = remoteData.fetch_ws(src_url)
            if not data:
                return False, "WebSocket connection failed", 0
            domains = []
            for line in data.splitlines():
                line = line.decode("utf-8")
                if line[0] == "D":
                    domains = line[1:].split(",")
                    break
            valid_domains = list(filter(check_valid_domains, [d.lower().strip(" .,;@") for d in domains]))
            return len(valid_domains) > 0, f"WS returned {len(valid_domains)} domains", len(valid_domains)

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

        if src_type == "json":
            lines = preprocess_json(source, data)
        elif src_type == "html":
            lines = preprocess_html(source, data)
        elif src_type == "list":
            lines = preprocess_file(source, data)
        elif src_type == "sha1":
            lines = preprocess_sha1(data)
        else:
            return False, f"Unknown type: {src_type}", 0

        if lines is None:
            return False, "Failed to parse data", 0

        if src_type == "sha1":
            return len(lines) > 0, f"SHA1 list returned {len(lines)} hashes", len(lines)

        domains = list(filter(check_valid_domains, [line.lower().strip(" .,;@") for line in lines]))

        if not domains:
            # Try fallback regex search
            fallback = [match.lower().strip(" .,;@") for match in DOMAIN_SEARCH_RE.findall(str(data))]
            domains = list(filter(check_valid_domains, fallback))

        return len(domains) > 0, f"Returned {len(domains)} valid domains", len(domains)

    except Exception as e:
        return False, f"Exception: {e}", 0


def main():
    print("=" * 80)
    print("DISPOSABLE EMAIL CRAWLER VERIFICATION")
    print("=" * 80)
    print()

    working = []
    broken = []

    for i, source in enumerate(sources, 1):
        name = source.get("name", source["src"])
        print(f"[{i}/{len(sources)}] Testing: {name}")
        print(f"      URL: {source['src'][:70]}..." if len(source["src"]) > 70 else f"      URL: {source['src']}")

        success, msg, count = verify_source(source)

        if success:
            print(f"      Status: {'WORKING' if count > 0 else 'WORKING (no new domains)'}")
            print(f"      Result: {msg}")
            working.append((name, msg))
        else:
            print(f"      Status: ** BROKEN **")
            print(f"      Reason: {msg}")
            broken.append((name, msg))

        print()

    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"\nWORKING ({len(working)}):")
    for name, msg in working:
        print(f"  [OK] {name}: {msg}")

    print(f"\nBROKEN ({len(broken)}):")
    for name, msg in broken:
        print(f"  [FAIL] {name}: {msg}")

    print(f"\nTotal: {len(working)} working, {len(broken)} broken out of {len(sources)} crawlers")


if __name__ == "__main__":
    main()
