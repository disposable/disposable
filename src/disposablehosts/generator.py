"""Main disposable email domain generator class."""

import concurrent.futures
import hashlib
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

import httpx
import tldextract
from websocket import create_connection

from .constants import (
    DISPOSABLE_GREYLIST_URL,
    DISPOSABLE_WHITELIST_URL,
    DOMAIN_RE,
    DOMAIN_SEARCH_RE,
    generate_random_string,
)
from .remote_data import remoteData
from .sources.file import fetch_file_source
from .sources.http import fetch_http_source
from .sources.websocket import fetch_websocket_source
from .utils.dns import fetch_MX


class DeltaCheckError(RuntimeError):
    """Raised when a run would remove too many domains (likely source outage)."""


class disposableHostGenerator:
    """Generator for collecting and validating disposable email domains."""

    sources: List[Dict[str, Any]] = [  # noqa: RUF012 - Mutable default is intentional, copied in __init__
        {"type": "list", "external": True, "src": "https://gist.githubusercontent.com/adamloving/4401361/raw/"},
        {"type": "list", "external": True, "src": "https://gist.githubusercontent.com/jamesonev/7e188c35fd5ca754c970e3a1caf045ef/raw/"},
        {"type": "list", "external": False, "src": "https://raw.githubusercontent.com/disposable/static-disposable-lists/master/mail-data-hosts-net.txt"},
        {"type": "list", "external": True, "src": "https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt"},
        {"type": "list", "external": False, "src": "https://raw.githubusercontent.com/disposable/static-disposable-lists/master/manual.txt"},
        {
            "type": "list",
            "external": True,
            "src": "https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable_email_blocklist.conf",
        },
        {"type": "list", "external": True, "src": "https://raw.githubusercontent.com/daisy1754/jp-disposable-emails/master/list.txt"},
        {"type": "list", "external": True, "src": "https://raw.githubusercontent.com/FGRibreau/mailchecker/master/list.txt"},
        {"type": "list", "external": True, "src": "https://raw.githubusercontent.com/7c/fakefilter/main/txt/data.txt"},
        # https://github.com/flotwig/disposable-email-addresses/ - no longer updated
        # {"type": "list", "external": True, "src": "https://raw.githubusercontent.com/flotwig/disposable-email-addresses/master/domains.txt"},
        {"type": "sha1", "external": True, "src": "https://raw.githubusercontent.com/GeroldSetz/Mailinator-Domains/master/mailinator_domains_from_bdea.cc.txt"},
        {
            "type": "list",
            "external": True,
            "src": "https://raw.githubusercontent.com/GeroldSetz/emailondeck.com-domains/refs/heads/master/emailondeck.com_domains_from_bdea.cc.txt",
        },
        {"type": "json", "src": "https://inboxes.com/api/v2/domain", "retain": True},
        {"type": "json", "src": "https://api.internal.temp-mail.io/api/v2/domains", "retain": True},
        {"type": "json", "src": "https://mailforspams.com/api/v1/domains", "retain": True},
        # fakemail.net - working again (HTTP 200)
        {"type": "html", "src": "https://www.fakemail.net/index/index", "regex": DOMAIN_SEARCH_RE, "retain": True},
        # mailpoof.com - DNS NXDOMAIN, service permanently offline
        # {"type": "json", "src": "https://api.mailpoof.com/domains"},
        # dropmail.me - WebSocket URL changed to /api/graphql/<token>/websocket, needs new implementation
        # {"type": "ws", "src": "wss://dropmail.me/websocket"},
        # tempmail.ninja - Nuxt SPA backed by a Socket.IO service (no domains in markup)
        {"type": "custom", "src": "TempmailNinja", "scrape": True, "retain": True},
        # tmp.al - luxusmail.org redirects here (HTTP 301), now an Android app
        # TODO: Investigate Android app - may need new extraction method
        # {"type": "html", "src": "https://tmp.al",
        #     "regex": re.compile(r"""<a.+?domain-selector\"[^>]+>@([a-z0-9\.-]{1,128})""", re.I)},
        # tempmailo.com - interactive Turnstile challenge, flaresolverr cannot solve
        # {"type": "custom", "src": "Tempmailo", "scrape": True},
        {"type": "custom", "src": "Tempamail", "retain": True},
        {"type": "custom", "src": "AdGuardTempMail", "scrape": True, "retain": True},
        # tmailor.com - cloudflare challenge, API returns HTTP 403
        # {"type": "custom", "src": "Tmailor", "scrape": True},
        # correotemporal.org - redirects to tempmail.ninja (HTTP 301)
        # {"type": "html", "src": "https://correotemporal.org", "regex": DOMAIN_SEARCH_RE},
        {"type": "file", "src": "blacklist.txt", "ignore_not_exists": True},
        {
            "type": "html",
            "src": "https://www.rotvpn.com/en/disposable-email",
            "regex": [
                re.compile(r"""<div class=\"container text-center\">\s+<div[^>]+>(.+?)</div>\s+</div>""", re.I | re.DOTALL),
                DOMAIN_SEARCH_RE,
            ],
            "retain": True,
        },
        {
            "type": "html",
            "src": "https://emailfake.com",
            "regex": re.compile(r"""change_dropdown_list[^"]+"[^>]+>@?([a-z0-9\.-]{1,128})""", re.I),
            "scrape": True,
            "retain": True,
        },
        {
            "type": "html",
            "src": "https://email-fake.com",
            "regex": re.compile(r"""change_dropdown_list[^"]+"[^>]+>@?([a-z0-9\.-]{1,128})""", re.I),
            "scrape": True,
            "retain": True,
        },
        {
            "type": "html",
            "src": "https://tempm.com",
            "regex": re.compile(r"""change_dropdown_list[^"]+"[^>]+>@?([a-z0-9\.-]{1,128})""", re.I),
            "scrape": True,
            "retain": True,
        },
        {
            "type": "html",
            "src": "https://mail-fake.com",
            "regex": re.compile(r"""change_dropdown_list[^"]+"[^>]+>@?([a-z0-9\.-]{1,128})""", re.I),
            "scrape": True,
            "retain": True,
        },
        {
            "type": "html",
            "src": "https://generator.email",
            "regex": re.compile(r"""change_dropdown_list[^"]+"[^>]+>@?([a-z0-9\.-]{1,128})""", re.I),
            "scrape": True,
            "retain": True,
        },
        {"type": "html", "src": "https://www.guerrillamail.com/en/", "retain": True},
        {"type": "html", "src": "https://www.trash-mail.com/inbox/", "retain": True},
        {
            "type": "html",
            "src": "https://mail-temp.com",
            "regex": re.compile(r"""change_dropdown_list[^"]+"[^>]+>@?([a-z0-9\.-]{1,128})""", re.I),
            "scrape": True,
            "retain": True,
        },
        {
            "type": "html",
            "src": "https://www.temporary-mail.net",
            "regex": re.compile(r"""<a.+?data-mailhost=\"@?([a-z0-9\.-]{1,128})\"""", re.I),
            "retain": True,
        },
        {
            "type": "html",
            "src": "https://nospam.today",
            "regex": [
                re.compile(r"""wire:initial-data="(.+?domains[^\"]+)\""""),
                re.compile(r"""\&quot;domains\&quot;:\[([^\]]+)\]"""),
                re.compile(r"""\&quot;([^\&]+)\&quot;"""),
            ],
            "retain": True,
        },
        {
            "type": "html",
            "src": "https://tempmail.plus/en/",
            "regex": re.compile(r"""<button type=\"button\" class=\"dropdown-item\">([^<]+)</button>""", re.I),
            "retain": True,
        },
        {
            "type": "html",
            "src": "https://spamok.nl/demo" + generate_random_string(8),
            "regex": re.compile(r"""<option\s+value="([^"]+)">""", re.I),
            "retain": True,
        },
        {
            "type": "html",
            "src": "https://tempr.email",
            "regex": re.compile(r"""<option\s+value[^>]*>@?([a-z\-\.\&#;\d+]+)\s*(\(PW\))?<\/option>""", re.I),
            "retain": True,
        },
        {
            "type": "html",
            "src": "https://yopmail.com/domain?d=all",
            "regex": [
                re.compile(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", re.I),
            ],
            "retain": True,
        },
    ]

    def __init__(
        self,
        options: Optional[Dict[str, Any]] = None,
        out_file: Optional[str] = None,
    ):
        """Initialize the DisposableHostGenerator.

        Args:
            options: Dictionary of configuration options.
            out_file: Path to output file (defaults to 'domains').
        """
        self.options = options or {}

        if not self.options.get("skip_src"):
            self.options["skip_src"] = []
        # Ensure skip_src is a list for type safety
        if not isinstance(self.options["skip_src"], list):
            self.options["skip_src"] = []

        log_level = logging.INFO if self.options.get("verbose") else logging.WARN
        if self.options.get("debug"):
            log_level = logging.DEBUG
        logging.basicConfig(format="%(levelname)s: %(message)s", level=log_level)

        logger = logging.getLogger("tldextract")
        logger.setLevel("WARNING")

        httpx_logger = logging.getLogger("httpx")
        httpx_logger.setLevel("WARNING")

        self.domains: Set[str] = set()
        self.legacy_domains: Set[str] = set()
        self.no_mx: List[str] = []
        self.old_domains: Set[str] = set()
        self.old_sha1: Set[str] = set()
        self.out_file = out_file or "domains"
        self.scrape: Set[str] = set()
        self.sha1: Set[str] = set()
        self.skip: Set[str] = set()
        self.grey: Set[str] = set()
        self.source_map: Dict[str, Union[Set[str], List[str]]] = {}
        self.source_cache: Dict[str, Dict[str, float]] = {}
        self._cache_written = False

        retention_days = self.options.get("retention_days")
        self.retention_days = 30 if retention_days is None else int(retention_days)
        max_delta_ratio = self.options.get("max_delta_ratio")
        self.max_delta_ratio = 0.2 if max_delta_ratio is None else float(max_delta_ratio)

        # Copy class sources to instance to avoid mutating ClassVar
        self.sources = list(self.sources)

        if self.options.get("file"):
            self.sources.insert(0, {"type": "file", "src": self.options["file"]})

        if os.environ.get("DUSTMAIL_API_KEY"):
            self.sources.append({"type": "custom", "src": "Dustmail", "retain": True})

        if os.environ.get("FLARESOLVERR_URL"):
            self.sources.append({"type": "custom", "src": "TempMailOrg", "scrape": True, "retain": True})

        # Load remote URL if no custom list is defined
        if self.options.get("whitelist") is None:
            self.sources.insert(0, {"type": "whitelist", "src": DISPOSABLE_WHITELIST_URL})
            self.options["whitelist"] = "whitelist.txt"
        else:
            self.sources.insert(
                0,
                {
                    "type": "whitelist_file",
                    "src": self.options.get("whitelist"),
                    "ignore_not_exists": self.options.get("whitelist") == "whitelist.txt",
                },
            )

        if self.options.get("greylist") is None:
            self.sources.insert(0, {"type": "greylist", "src": DISPOSABLE_GREYLIST_URL})
        else:
            self.sources.insert(
                0,
                {
                    "type": "greylist_file",
                    "src": self.options.get("greylist"),
                    "ignore_not_exists": self.options.get("greylist") == "greylist.txt",
                },
            )

    def _fetch_data(self, source: Dict[str, Any]) -> bytes:
        """Fetch data from the specified source.

        Args:
            source: Source dictionary containing type and src information.

        Returns:
            Fetched data as bytes.
        """
        if source.get("type") in ("file", "whitelist_file", "greylist_file"):
            return fetch_file_source(source["src"], source.get("ignore_not_exists", False))
        elif source.get("type") == "custom":
            return getattr(self, f"_process{source['src']}")()
        elif source.get("type") == "ws":
            return fetch_websocket_source(source["src"])

        headers = {}
        if source.get("type") == "json":
            headers["Accept"] = "application/json, text/javascript, */*; q=0.01"
            headers["X-Requested-With"] = "XMLHttpRequest"

        return fetch_http_source(
            source["src"],
            headers,
            source.get("timeout", 3),
            max_retry=int(self.options.get("max_retry", 1)),
        )

    def _preprocess_sha1(self, data: bytes) -> None:
        """Preprocess SHA1 data.

        Args:
            data: Raw SHA1 hash data.
        """
        from .preprocessing.sha1 import preprocess_sha1

        preprocess_sha1(data, self.sha1)

    def _preprocess_data(self, source: Dict[str, Any], data: bytes) -> Optional[List[str]]:
        """Preprocess data based on source type.

        Args:
            source: Source dictionary with type information.
            data: Raw data to preprocess.

        Returns:
            List of preprocessed strings, or None if unhandled.
        """
        if isinstance(data, list):
            return data

        fmt = source["type"]

        if fmt == "sha1":
            self._preprocess_sha1(data)
            return []

        if fmt == "ws":
            from .preprocessing.websocket import preprocess_websocket

            return preprocess_websocket(data)

        if fmt == "html":
            from .preprocessing.html import preprocess_html

            return preprocess_html(data, source.get("regex"), source.get("encoding", "utf-8"))

        if fmt == "json":
            from .preprocessing.json import preprocess_json

            return preprocess_json(data, source.get("encoding", "utf-8"))

        # Handle file-based types (list, file, whitelist, greylist, etc.)
        if fmt in ("whitelist", "list", "file", "whitelist_file", "greylist", "greylist_file"):
            from .preprocessing.file import preprocess_file

            return preprocess_file(data, source.get("encoding", "utf-8"))

        return None

    def _postprocess_data(self, source: Dict[str, Any], data: bytes, lines: List[str]) -> Union[bool, Tuple[int, int]]:
        """Post-process data obtained from a source.

        Args:
            source: Source of the data.
            data: Raw data obtained from the source.
            lines: Preprocessed lines.

        Returns:
            True if source is whitelist/greylist, False if no results,
            or tuple of (added_count, found_count).
        """
        lines_filtered = self._filter_source_hosts(source, data, lines)

        if source["type"] in ("whitelist", "whitelist_file", "sha1"):
            self.skip.update(lines_filtered)
            return True

        if source["type"] in ("greylist", "greylist_file"):
            self.grey.update(lines_filtered)
            return True

        if not lines_filtered:
            logging.warning("No results for source %s", source)
            return False

        self.source_map[source["src"]] = self.scrape if source.get("scrape") else lines_filtered

        if self._source_retains(source):
            cache_entry = self.source_cache.setdefault(str(source["src"]), {})
            now = time.time()
            for host in lines_filtered:
                cache_entry[host] = now

        added_domains, added_scrape_domains = self._merge_domains(source, lines_filtered)

        logging.debug("Example domain: %s", lines_filtered[0])

        if source.get("scrape"):
            logging.debug("Added %s scraped domains: %s", len(added_scrape_domains), added_scrape_domains)
            return len(added_scrape_domains), len(lines_filtered)

        return added_domains, len(lines_filtered)

    def _filter_source_hosts(self, source: Dict[str, Any], data: bytes, lines: List[str]) -> List[str]:
        """Normalize source lines to valid domains.

        Falls back to a domain regex over the raw data when no valid lines are
        found, and strips the source's own hostname artifacts for html sources.
        """
        lines_filtered = [line.lower().strip(" .,;@") for line in lines]
        lines_filtered = list(filter(self.check_valid_domains, lines_filtered))

        if not lines_filtered:
            fallback_lines = [match.lower().strip(" .,;@") for match in DOMAIN_SEARCH_RE.findall(str(data))]
            lines_filtered = list(filter(self.check_valid_domains, fallback_lines))

        if source["type"] == "html":
            src_host = urlparse(str(source.get("src", ""))).hostname
            if src_host:
                src_host = src_host.lower()
                lines_filtered = [host for host in lines_filtered if host == src_host or not src_host.endswith(host) or src_host.endswith("." + host)]

        return lines_filtered

    def _merge_domains(self, source: Dict[str, Any], lines_filtered: List[str]) -> Tuple[int, List[str]]:
        """Merge validated hosts into domains/legacy/sha1/scrape sets.

        Returns:
            Tuple of (number of newly added domains, list of new scrape domains).
        """
        added_domains = 0
        added_scrape_domains: List[str] = []
        for host in lines_filtered:
            if host not in self.domains:
                self.domains.add(host)
                added_domains += 1

            self.legacy_domains.add(host)

            try:
                self.sha1.add(hashlib.sha1(host.encode("idna")).hexdigest())  # nosec B324 - SHA1 used for domain hashing, not security
            except Exception:  # nosec B110 - Intentional fallback for encoding errors
                pass

            if source.get("scrape") and host not in self.scrape:
                self.scrape.add(host)
                added_scrape_domains.append(host)
        return added_domains, added_scrape_domains

    def process(self, source: Dict[str, Any]) -> bool:
        """Process the given source and generate disposable data.

        Args:
            source: Dictionary containing source information.

        Returns:
            True if process was successful, False otherwise.
        """
        logging.debug("Process %s (%s)", source["src"], source["type"])
        if self.options.get("skip_scrape") and source.get("scrape"):
            logging.debug("Skipping scraping source %s", source["src"])
            source["scrape"] = False

        max_scrape = 80
        scrape_max_retry = 3
        scrape_count = 0
        self.scrape = set()
        scrape_retry = 0

        while scrape_count < max_scrape:
            data = self._fetch_data(source)
            if data is None:
                logging.warning("No results by %s", source["src"])
                return False

            logging.debug("Fetched %s bytes", len(data))
            lines = self._preprocess_data(source, data)
            if lines is None:
                return False

            res = self._postprocess_data(source, data, lines)
            if isinstance(res, bool):
                return res

            (processed_entries, found_entries) = res

            logging.debug("Processed %s entries (%s found)", processed_entries, found_entries)
            if source.get("scrape"):
                if processed_entries:
                    scrape_retry = 0
                else:
                    scrape_retry += 1
                    if scrape_retry > scrape_max_retry:
                        return True
                time.sleep(source.get("timeout", 8))
                continue
            return True
        return False

    def _processTempmailo(self) -> Optional[List[str]]:
        """Fetch disposable email domains from tempmailo.com.

        Returns:
            List of domain strings, or None if request fails.
        """
        from .sources.http import fetch_http_source_raw

        res = fetch_http_source_raw("https://tempmailo.com/")
        if res is None:
            return None

        cookies = {}
        for ky, vl in res.headers.items():
            if ky.lower() != "set-cookie":
                continue

            (ck_name, ck_data) = vl.split("=", 1)
            if ck_name.startswith("__"):
                continue
            (ck_value, _) = ck_data.split(";", 1)
            cookies[ck_name] = ck_value

        body = res.read().decode("utf8")

        f = re.search('name="__RequestVerificationToken".+?value="([^"]+)"', body)
        if not f:
            logging.warning("Failed to fetch __RequestVerificationToken")
            return None

        headers = {
            "requestverificationtoken": f[1],
            "accept": "application/json, text/plain, */*",
            "x-requested-with": "XMLHttpRequest",
            "referer": "https://tempmailo.com/",
            "cookie": "; ".join([f"{ky}={vl}" for ky, vl in cookies.items()]),
        }

        data = fetch_http_source("https://tempmailo.com/changemail", headers)
        if not data:
            logging.warning("Failed to fetch https://tempmailo.com/changemail endpoint")
            return None

        lines = []
        for line in data.splitlines():
            (_, domain) = line.decode("utf8").split("@", 1)
            lines.append(domain)

        return lines

    def _processTempamail(self) -> Optional[List[str]]:
        """Fetch disposable email domains from the tempamail.com webapp API.

        Returns:
            List of domain strings, or None if request fails.
        """
        try:
            client = httpx.post(
                "https://api.tempamail.com/webapp/client/create",
                json={"app_uuid": "a5x-cj6a-ka1q"},
                timeout=15,
            ).json()
            res = httpx.post(
                "https://api.tempamail.com/webapp/domains",
                json={"uuid": client["client"]["uuid"]},
                timeout=15,
            ).json()
            return [d["name"] for d in res.get("domains", []) if d.get("name")]
        except Exception as e:
            logging.warning("Failed to fetch tempamail.com domains: %s", e)
            return None

    def _processDustmail(self) -> Optional[List[str]]:
        """Fetch shared inbox domains from dustmail.net (requires DUSTMAIL_API_KEY).

        Returns:
            List of domain strings, or None if request fails.
        """
        try:
            res = httpx.post(
                "https://dustmail.net/api/v1/inbox",
                headers={"Authorization": f"Bearer {os.environ['DUSTMAIL_API_KEY']}"},
                timeout=15,
            ).json()
            return [d for d in res.get("meta", {}).get("available_domains", []) if d]
        except Exception as e:
            logging.warning("Failed to fetch dustmail.net domains: %s", e)
            return None

    def _processAdGuardTempMail(self) -> Optional[List[str]]:
        """Fetch a list of disposable email domains from AdGuard Temp Mail.

        Note: AdGuard Temp Mail uses dynamic JavaScript loading and may require
        CAPTCHA, so we maintain a list of known domains from this service.

        Returns:
            List of domain strings.
        """
        # Known domains used by AdGuard Temp Mail service
        # These are observed domains from the service
        known_domains = [
            "protectsmail.net",
            "rapidletter.net",
            "concu.net",
        ]

        # Try to fetch additional domains from the page if possible
        try:
            data = remoteData.fetch_http("https://tempmail.adguard.com/", timeout=5)
            if data:
                html_content = data.decode("utf-8")

                # Look for domain patterns in the HTML
                domain_matches = re.findall(r"@([a-z0-9.-]+\.[a-z]{2,})", html_content, re.I)
                if domain_matches:
                    known_domains.extend(domain_matches)

                # Also check for domains in JavaScript variables or data attributes
                js_domains = re.findall(
                    r'domain["\']?\s*:\s*["\']([a-z0-9.-]+\.[a-z]{2,})["\']',
                    html_content,
                    re.I,
                )
                if js_domains:
                    known_domains.extend(js_domains)
        except Exception as e:
            logging.debug("Could not fetch dynamic domains from AdGuard: %s", e)

        return list(set(known_domains))

    def _processTmailor(self) -> Optional[List[str]]:
        """Fetch a list of disposable email domains from tmailor.com.

        Note: Tmailor uses dynamic domain generation. This scraper attempts to
        fetch domains from the service by sampling newly created addresses.

        Returns:
            List of domain strings.
        """
        headers = {
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.5",
            "content-type": "application/json",
            "origin": "https://tmailor.com",
            "referer": "https://tmailor.com/en/",
            "user-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0",
        }

        max_attempts = 15
        domains: List[str] = []

        for _ in range(max_attempts):
            payload = {
                "action": "newemail",
                "curentToken": "",
            }
            try:
                data = remoteData.fetch_http_post("https://tmailor.com/api", headers=headers, json_data=payload, timeout=8)
            except Exception as exc:  # pragma: no cover - network quirks
                logging.debug("Failed to talk to tmailor API: %s", exc)
                continue

            if not data:
                continue

            try:
                resp = json.loads(data.decode("utf-8"))
            except Exception as exc:
                logging.debug("Invalid JSON from tmailor: %s", exc)
                continue

            email = resp.get("email")
            if not email:
                continue

            _, _, domain = email.partition("@")
            if domain and self.check_valid_domains(domain):
                domains.append(domain)

        domains = list(set(domains))
        if not domains:
            logging.warning("No domains found for tmailor.com")

        return domains

    def _processTempmailNinja(self) -> Optional[List[str]]:
        """Fetch disposable email domains from tempmail.ninja via its Socket.IO backend.

        The webapp is a Nuxt SPA that talks to a Socket.IO service at
        tm-app.solucioneswc.com:2083. The `get_domains` event returns the
        selectable domain pool for a given `domainType`; we query a small
        range and merge all pools. The auto-assigned mailbox pool is separate:
        `get_guest_user_data` with a null token creates a guest session bound
        to the socket, after which `generate_temp_mail` returns a fresh
        mailbox whose domain we also collect.

        Returns:
            List of domain strings, or None if the backend is unreachable.
        """
        ws_url = "wss://tm-app.solucioneswc.com:2083/socket.io/?locale=en&EIO=4&transport=websocket"
        domain_types = range(6)
        gen_id = len(domain_types) + 1
        domains: Set[str] = set()
        try:
            ws = create_connection(ws_url, origin="https://tempmail.ninja", timeout=15)
            try:

                def recv_text() -> str:
                    m = ws.recv()
                    return m.decode("utf-8", "replace") if isinstance(m, bytes) else m

                ws.recv()  # Engine.IO open packet: 0{...}
                ws.send("40")  # Socket.IO connect
                ws.recv()  # connect ack: 40{...} (or 44 error)

                # bootstrap a guest session so generate_temp_mail works
                ws.send('420["get_guest_user_data",{"token":null}]')
                ws.settimeout(10)
                try:
                    msg = ""
                    while not msg.startswith("43"):
                        msg = recv_text()
                except Exception as e:
                    logging.debug("tempmail.ninja guest session bootstrap failed: %s", e)

                for req_id, domain_type in enumerate(domain_types, 1):
                    ws.send(f'42{req_id}["get_domains",{{"domainType":{domain_type}}}]')
                ws.send(f'42{gen_id}["generate_temp_mail"]')

                ws.settimeout(15)
                acks = 0
                expected = len(domain_types) + 1
                deadline = time.time() + 20
                while acks < expected and time.time() < deadline:
                    try:
                        msg = recv_text()
                    except Exception:
                        break
                    if msg == "2":  # Engine.IO ping -> pong
                        ws.send("3")
                        continue
                    if self._ninja_handle_ack(msg, gen_id, domains):
                        acks += 1
            finally:
                ws.close()
        except Exception as e:
            logging.warning("Failed to fetch tempmail.ninja domains: %s", e)
            return None

        if not domains:
            logging.warning("No domains found for tempmail.ninja")

        return sorted(domains)

    def _ninja_handle_ack(self, msg: str, gen_id: int, domains: Set[str]) -> bool:
        """Handle one tempmail.ninja Socket.IO message.

        Args:
            msg: Raw text frame.
            gen_id: Request id of the ``generate_temp_mail`` call.
            domains: Set to collect domains into.

        Returns:
            True if the message was a request ack (``43<id>[...]``), False for
            pings, server events and other non-ack frames.
        """
        m = re.match(r"43(\d+)(\[.*\])$", msg, re.S)
        if not m:
            return False  # server events like connection_warning
        try:
            payload = json.loads(m.group(2))
        except ValueError:
            return True
        if not payload or not isinstance(payload[0], dict):
            return True
        if int(m.group(1)) == gen_id:
            domain = (payload[0].get("emailData") or {}).get("domain")
            if domain:
                domains.add(domain.lower())
            return True
        for entry in payload[0].get("domains") or []:
            name = entry.get("name")
            if name and entry.get("status") == 1:
                domains.add(name.lower())
        return True

    def _processTempMailOrg(self) -> Optional[List[str]]:
        """Fetch the currently assigned mailbox domain from temp-mail.org via FlareSolverr.

        temp-mail.org assigns one rotating domain per session and its public
        domain API is stale (issue #260). POST https://web2.temp-mail.org/mailbox
        through FlareSolverr creates a fresh mailbox and returns its domain.

        When FLARESOLVERR_PROXIES is set (comma-separated proxy URLs), one
        request per proxy is sent - each egresses from a different IP, so the
        per-IP rate limit does not collide and each request may land in a
        different rotation window. Without proxies, a few spaced attempts can
        still catch a mid-run rotation; the backend rate-limits per IP, so we
        stop on failure.

        Returns:
            List of domain strings, or None if unreachable.
        """
        proxies = [p.strip() for p in os.environ.get("FLARESOLVERR_PROXIES", "").split(",") if p.strip()]
        domains: Set[str] = set()
        if proxies:
            for proxy in proxies:
                domain = self._tempmailorg_sample(proxy)
                if domain:
                    domains.add(domain)
        else:
            for _ in range(5):
                domain = self._tempmailorg_sample()
                if not domain:
                    break  # rate limited or unreachable
                domains.add(domain)
                time.sleep(20)

        if not domains:
            logging.warning("No domains found for temp-mail.org")
            return None

        return sorted(domains)

    def _tempmailorg_sample(self, proxy: Optional[str] = None) -> Optional[str]:
        """Create one mailbox on temp-mail.org and return its domain."""
        try:
            data = remoteData.fetch_flaresolverr("https://web2.temp-mail.org/mailbox", timeout=45, post_data="{}", proxy=proxy)
        except Exception as e:
            logging.debug("temp-mail.org mailbox request failed: %s", e)
            return None
        m = re.search(rb'"mailbox"\s*:\s*"[^"@]*@([a-z0-9.-]+\.[a-z]{2,})"', data or b"")
        if not m:
            return None
        return m.group(1).decode().lower()

    def read_files(self) -> None:
        """Read and compare to current (old) domains file."""
        self.old_domains = set()
        try:
            with open(f"{self.out_file}.txt") as f:
                for line in f:
                    self.old_domains.add(line.strip())
        except FileNotFoundError:
            # Expected on first run - optional file may not exist yet
            pass

        self.old_sha1 = set()
        try:
            with open(f"{self.out_file}_sha1.txt") as f:
                for line in f:
                    self.old_sha1.add(line.strip())
        except FileNotFoundError:
            # Expected on first run - optional file may not exist yet
            pass

        self.legacy_domains = set()
        try:
            with open(f"{self.out_file}_legacy.txt") as f:
                for line in f:
                    self.legacy_domains.add(line.strip())
        except FileNotFoundError:
            # Expected on first run - optional file may not exist yet
            pass

    def _source_retains(self, source: Dict[str, Any]) -> bool:
        """Whether a source's seen domains are retained across runs.

        Opt-in per source via the ``retain`` flag - set on sources we crawl
        ourselves so a transient failure or rotating domain pool does not drop
        previously seen domains. Upstream compilations stay unflagged.
        """
        return bool(source.get("retain", False))

    def _load_source_cache(self) -> None:
        """Load the per-source retention cache next to the output file."""
        path = os.path.join(os.path.dirname(self.out_file) or ".", "source_cache.json")
        try:
            with open(path) as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                self.source_cache = {str(src): {str(d): float(ts) for d, ts in entries.items()} for src, entries in raw.items() if isinstance(entries, dict)}
        except (FileNotFoundError, ValueError, OSError):
            # Expected on first run or after cache cleanup - start empty
            pass

    def _write_source_cache(self) -> None:
        """Persist the per-source retention cache, pruning expired entries."""
        if self._cache_written:
            return
        self._cache_written = True
        path = os.path.join(os.path.dirname(self.out_file) or ".", "source_cache.json")
        cutoff = time.time() - self.retention_days * 86400
        cache = {src: {d: ts for d, ts in entries.items() if ts >= cutoff} for src, entries in self.source_cache.items()}
        cache = {src: entries for src, entries in cache.items() if entries}
        with open(path, "w") as f:
            json.dump(cache, f, indent=2, sort_keys=True)

    def _apply_retention(self) -> None:
        """Merge non-expired cached domains of crawled sources into the result.

        Rotating-pool samplers only return the currently active domain(s), and
        transient failures would otherwise drop a source's contribution. Cached
        domains are merged before whitelisting so the whitelist still applies.
        """
        if not self.retention_days:
            return
        if not self.source_cache:
            self._load_source_cache()

        cutoff = time.time() - self.retention_days * 86400
        retained = 0
        for entries in self.source_cache.values():
            for host, seen in entries.items():
                if seen >= cutoff and host not in self.domains and self.check_valid_domains(host):
                    self.domains.add(host)
                    self.legacy_domains.add(host)
                    retained += 1
                    try:
                        self.sha1.add(hashlib.sha1(host.encode("idna")).hexdigest())  # nosec B324 - SHA1 used for domain hashing, not security
                    except Exception:  # nosec B110 - Intentional fallback for encoding errors
                        pass
        if retained:
            logging.info("Retained %s domain(s) from source cache", retained)

    def check_valid_domains(self, host: str) -> bool:
        """Check if the given host is a valid domain name.

        Args:
            host: The host to check.

        Returns:
            True if valid domain, False otherwise.
        """
        try:
            if not DOMAIN_RE.match(host):
                return False

            t = tldextract.extract(host)
            return t.domain != "" and t.suffix != ""
        except Exception:  # nosec B110 - Intentional fallback for domain validation
            pass

        return False

    def list_sources(self) -> None:
        """List all available sources."""
        for source in self.sources:
            logging.info("Source %12s: %s", source.get("type"), source.get("src"))

    def add_greylist(self) -> None:
        """Add greylist to domains + sha1."""
        self.domains.update(self.grey)
        for host in self.grey:
            try:
                self.sha1.add(hashlib.sha1(host.encode("idna")).hexdigest())  # nosec B324 - SHA1 used for domain hashing, not security
            except Exception:  # nosec B110 - Intentional fallback for encoding errors
                pass
        self.source_map["greylist"] = self.grey

    def _should_skip_source(self, source: Dict[str, Any]) -> bool:
        """Check if a source should be skipped based on filter/skip options."""
        skip_src_list = self.options.get("skip_src", [])
        if not isinstance(skip_src_list, list):
            skip_src_list = []
        return (
            source["src"] not in ("whitelist_file", "greylist_file")
            and self.options.get("src_filter") is not None
            and source["src"] != self.options.get("src_filter")
        ) or source["src"] in skip_src_list

    def _fetch_sources(self) -> None:
        """Fetch and process data from all configured sources."""
        for source in self.sources:
            if self._should_skip_source(source):
                continue

            try:
                if not self.process(source) and self.options.get("debug"):
                    raise RuntimeError(f"No result for {source}")
            except Exception as err:
                logging.exception(err)
                raise err

    def _get_dns_options(self) -> Tuple[Optional[List[str]], Optional[int], int]:
        """Extract and validate DNS options."""
        nameservers = self.options.get("nameservers")
        if not isinstance(nameservers, list):
            nameservers = None
        dnsport = self.options.get("dnsport")
        if not isinstance(dnsport, int):
            dnsport = None
        dns_timeout_val = self.options.get("dns_timeout", 20)
        if isinstance(dns_timeout_val, bool) or not isinstance(dns_timeout_val, (int, float)):
            dns_timeout_val = 20
        return nameservers, dnsport, int(dns_timeout_val)

    def _apply_whitelist(self) -> None:
        """Remove whitelisted domains and verify DNS if enabled."""
        skip = self.skip.copy()
        if not self.options.get("strict"):
            skip.update(self.grey)

        nameservers, dnsport, dns_timeout = self._get_dns_options()

        for domain in skip:
            self.domains.discard(domain)
            self.sha1.discard(hashlib.sha1(domain.encode("idna")).hexdigest())  # nosec B324

            if self.options.get("dns_verify") and domain not in ("example.com", "example.org", "example.net"):
                r = fetch_MX(domain, nameservers, dnsport, dns_timeout)
                if not r or not r[1]:
                    logging.warning("Skipped domain %s does not resolve!", domain)

    def _verify_mx_records(self) -> None:
        """Verify MX records for all domains using thread pool."""
        self.no_mx = []
        if not self.options.get("dns_verify"):
            return

        nameservers, dnsport, dns_timeout = self._get_dns_options()
        dns_threads = self.options.get("dns_threads", 1)
        if not isinstance(dns_threads, int):
            dns_threads = 1

        with concurrent.futures.ThreadPoolExecutor(max_workers=dns_threads) as executor:
            futures = [executor.submit(fetch_MX, domain, nameservers, dnsport, dns_timeout) for domain in self.domains]
            for future in concurrent.futures.as_completed(futures):
                (domain, valid) = future.result()
                if not valid:
                    self.no_mx.append(domain)

    def _log_generation_results(self) -> bool:
        """Log results and return whether changes were detected."""
        if not self.options.get("verbose"):
            return True

        if not self.old_domains:
            self.read_files()

        added = list(filter(lambda domain: domain not in self.old_domains, self.domains))
        removed = list(filter(lambda domain: domain not in self.domains, self.old_domains))
        added_sha1 = list(filter(lambda sha_str: sha_str not in self.old_sha1, self.sha1))
        removed_sha1 = list(filter(lambda sha_str: sha_str not in self.sha1, self.old_sha1))

        logging.info("Fetched %s domains and %s hashes", len(self.domains), len(self.sha1))
        if self.options.get("dns_verify"):
            logging.info(" - %s domain(s) have no MX", len(self.no_mx))
            if self.options.get("list_no_mx"):
                logging.info("No MX: %s", self.no_mx)
        logging.info(" - %s domain(s) added", len(added))
        logging.info(" - %s domain(s) removed", len(removed))
        logging.info(" - %s hash(es) added", len(added_sha1))
        logging.info(" - %s hash(es) removed", len(removed_sha1))

        # Stop if nothing has changed
        if len(added) == len(removed) == len(added_sha1) == len(removed_sha1) == 0:
            return False

        if self.options.get("src_filter"):
            logging.info("Fetched: %s", self.domains)
        return True

    def _enforce_max_delta(self) -> None:
        """Abort the run when too many domains would be removed.

        A mass removal usually indicates a source outage or broken fetch rather
        than legitimate upstream churn. Raises before any output is written so
        callers (update.sh) keep the previous list.
        """
        if not self.max_delta_ratio:
            return
        if self.options.get("src_filter") or self.options.get("file"):
            return  # partial runs are not representative
        if not self.old_domains:
            self.read_files()
        if not self.old_domains:
            return  # first run

        removed = self.old_domains - self.domains
        min_abs_change = 50
        if len(removed) > min_abs_change and len(removed) / len(self.old_domains) > self.max_delta_ratio:
            raise DeltaCheckError(
                f"Delta check failed: {len(removed)} of {len(self.old_domains)} domains would be removed "
                f"(> {self.max_delta_ratio:.0%}). Refusing to write output."
            )

    def generate(self) -> bool:
        """Fetch all data and generate lists.

        Returns:
            True if data was fetched and there are changes, False otherwise.
        """
        self._load_source_cache()
        self._fetch_sources()
        self._apply_retention()
        self._apply_whitelist()
        self._verify_mx_records()
        changed = self._log_generation_results()
        self._enforce_max_delta()
        return changed

    def write_to_file(self) -> None:
        """Write new list to file(s)."""
        self._write_source_cache()
        domains = sorted(self.domains)
        with open(f"{self.out_file}.txt", "w") as ff:
            ff.write("\n".join(domains))

        with open(f"{self.out_file}.json", "w") as ff:
            ff.write(json.dumps(domains))

        if self.options.get("source_map"):
            with open(f"{self.out_file}_source_map.txt", "w") as ff:
                for src_url, source_map_domains in sorted(self.source_map.items()):
                    ff.write(f"{src_url}:" + ("\n%s:" % src_url).join(sorted(source_map_domains)) + "\n")

        if self.no_mx:
            domains_with_mx = set(self.domains)
            for domain in self.no_mx:
                domains_with_mx.discard(domain)

            domains = sorted(domains_with_mx)
            with open(f"{self.out_file}_mx.txt", "w") as ff:
                ff.write("\n".join(domains))

            with open(f"{self.out_file}_mx.json", "w") as ff:
                ff.write(json.dumps(domains))

        # Write new hash list to file(s)
        domains_sha1 = sorted(self.sha1)
        with open(f"{self.out_file}_sha1.txt", "w") as ff:
            ff.write("\n".join(domains_sha1))

        with open(f"{self.out_file}_sha1.json", "w") as ff:
            ff.write(json.dumps(domains_sha1))
