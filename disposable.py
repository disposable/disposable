#!/usr/bin/env python3
from typing import Any, Dict, List, Optional, Union, Tuple
import functools
import json
import re
import sys
import hashlib
import html
import time
import tldextract
import argparse
import dns.resolver
import dns.rdatatype
import dns.exception
import concurrent.futures
import logging
import httpx
import ipaddress
import random
import string
from websocket import create_connection

RETRY_ERRORS_RE = re.compile(r"""(The read operation timed out|urlopen error timed out)""", re.I)
DOMAIN_RE = re.compile(r'^[a-z\d-]{1,63}(\.[a-z-\.]{2,63})+$')
DOMAIN_SEARCH_RE = re.compile(r'["\'\s>]([a-z\d\.-]{1,63}\.[a-z\-]{2,63})["\'\s<]', re.I)
HTML_GENERIC_RE = re.compile(r"""<option[^>]*>@?([a-z0-9\-\.\&#;\d+]+)\s*(\(PW\))?<\/option>""", re.I)
SHA1_RE = re.compile(r'^[a-fA-F0-9]{40}')

DISPOSABLE_WHITELIST_URL = 'https://raw.githubusercontent.com/disposable/disposable/master/whitelist.txt'
DISPOSABLE_GREYLIST_URL = 'https://raw.githubusercontent.com/disposable/disposable/master/greylist.txt'


def generate_random_string(length: int) -> str:
    """
    Generates a random string of lowercase letters with the specified length.

    Args:
        length (int): The length of the string to generate.

    Returns:
        str: A random string of lowercase letters with the specified length.
    """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


class remoteData():

    @staticmethod
    def fetch_file(src: str, ignore_errors: Optional[bool] = False) -> bytes:
        """
        Reads the contents of a file and returns it as bytes.

        Args:
            src (str): The path to the file to read.
            ignore_errors (bool, optional): Whether to ignore errors if the file is not found or cannot be read. Defaults to False.

        Returns:
            bytes: The contents of the file as bytes.

        Raises:
            FileNotFoundError: If the file is not found and ignore_errors is False.
            IOError: If there is an error reading the file and ignore_errors is False.
        """
        try:
            with open(src, 'rb') as f:
                return f.read()
        except FileNotFoundError as e:
            if ignore_errors:
                return b''
            raise e
        except IOError as e:
            if ignore_errors:
                return b''
            raise e

    @staticmethod
    def fetch_ws(src: str) -> bytes:
        """
        Fetches data from a WebSocket connection (first 3 messages)

        Args:
            src (str): The WebSocket URL to connect to.

        Returns:
            bytes: The data received from the WebSocket connection.
        """
        try:
            ws = create_connection(src)
            data = []
            for _ in range(3):
                line = ws.recv()
                if type(line) is str:
                    line = line.encode('utf-8')
                data.append(line)
            ws.close()
        except IOError as e:
            logging.exception(e)
            return b''

        return b'\n'.join(data)

    @staticmethod
    def fetch_http_raw(url: str,
                       headers: Optional[Dict[str, str]] = None,
                       timeout: Optional[int] = None,
                       max_retry: Optional[int] = None) -> Optional[httpx.Response]:
        """
        Fetches the raw HTTP response for a given URL.

        Args:
            url (str): The URL to fetch.
            headers (Optional[Dict[str, str]]): Optional headers to include in the request.
            timeout (Optional[int]): Optional timeout for the request in seconds.
            max_retry (Optional[int]): Optional maximum number of retries if the request fails.

        Returns:
            Optional[httpx.Response]: The HTTP response, or None if the request failed.
        """
        if not headers:
            headers = {}

        if timeout is None:
            timeout = 3

        if max_retry is None:
            max_retry = 150

        retry = 0
        headers.setdefault('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/118.0')
        headers.setdefault('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
        with httpx.Client(http2=True, verify=False) as client:
            while retry < max_retry:
                try:
                    return client.get(url, headers=headers, timeout=timeout)
                except Exception as e:
                    retry += 1
                    logging.error(e)
                    if RETRY_ERRORS_RE.search(str(e)) and retry < max_retry:
                        time.sleep(1)
                        continue

                    logging.warning('Fetching URL %s failed, see error: %s', url, e)
                    break

    @staticmethod
    def fetch_http(url: str,
                   headers: Optional[Dict[str, str]] = None,
                   timeout: Optional[int] = None,
                   max_retry: Optional[int] = None) -> bytes:
        """
        Fetches the content of a given URL using HTTP GET method.
        Calls fetch_http_raw and returns the content of the response as bytes if the request was successful.

        Args:
            url (str): The URL to fetch.
            headers (Optional[Dict[str, str]]): Optional headers to include in the request.
            timeout (Optional[int]): Optional timeout for the request in seconds.
            max_retry (Optional[int]): Optional maximum number of retries if the request fails.

        Returns:
            bytes: The content of the response as bytes.

        """
        res = remoteData.fetch_http_raw(url, headers, timeout, max_retry)
        return (res and res.read()) or b''


class disposableHostGenerator():
    sources = [
        {'type': 'list', 'src': 'https://gist.githubusercontent.com/adamloving/4401361/raw/'},
        {'type': 'list', 'src': 'https://gist.githubusercontent.com/jamesonev/7e188c35fd5ca754c970e3a1caf045ef/raw/'},
        {'type': 'list', 'src': 'https://raw.githubusercontent.com/disposable/static-disposable-lists/master/mail-data-hosts-net.txt'},
        {'type': 'list', 'src': 'https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt'},
        {'type': 'list', 'src': 'https://raw.githubusercontent.com/disposable/disposable/master/blacklist.txt'},
        {'type': 'list', 'src': 'https://www.stopforumspam.com/downloads/toxic_domains_whole.txt'},
        {'type': 'list', 'src': 'https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable_email_blocklist.conf'},
        {'type': 'list', 'src': 'https://raw.githubusercontent.com/daisy1754/jp-disposable-emails/master/list.txt'},
        {'type': 'list', 'src': 'https://raw.githubusercontent.com/FGRibreau/mailchecker/master/list.txt'},
        {'type': 'json', 'src': 'https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json'},
        {'type': 'list', 'src': 'https://raw.githubusercontent.com/7c/fakefilter/main/txt/data.txt'},
        {'type': 'list', 'src': 'https://raw.githubusercontent.com/flotwig/disposable-email-addresses/master/domains.txt'},
        {'type': 'json', 'src': 'https://inboxes.com/api/v2/domain'},
        # currently blocked by cloudflare
        # {'type': 'json', 'src': 'https://mob1.temp-mail.org/request/domains/format/json'},
        {'type': 'json', 'src': 'https://api.internal.temp-mail.io/api/v2/domains'},
        {'type': 'json', 'src': 'https://www.fakemail.net/index/index', 'scrape': True},
        {'type': 'json', 'src': 'https://api.mailpoof.com/domains'},
        {'type': 'file', 'src': 'blacklist.txt', 'ignore_not_exists': True},
        {'type': 'sha1', 'src': 'https://raw.githubusercontent.com/GeroldSetz/Mailinator-Domains/master/mailinator_domains_from_bdea.cc.txt'},
        {
            'type': 'html',
            'src': 'https://www.rotvpn.com/en/disposable-email',
            'regex': [
                re.compile(r"""<div class=\"container text-center\">\s+<div[^>]+>(.+?)</div>\s+</div>""", re.I | re.DOTALL),
                DOMAIN_SEARCH_RE
            ]
        },
        {'type': 'html', 'src': 'https://emailfake.com',
            'regex': re.compile(r"""change_dropdown_list[^"]+"[^>]+>@?([a-z0-9\.-]{1,128})""", re.I), 'scrape': True},
        {'type': 'html', 'src': 'https://www.guerrillamail.com/en/'},
        {'type': 'html', 'src': 'https://www.trash-mail.com/inbox/'},
        {'type': 'html', 'src': 'https://mail-temp.com', 'regex':
            re.compile(r"""change_dropdown_list[^"]+"[^>]+>@?([a-z0-9\.-]{1,128})""", re.I), 'scrape': True},
        # currently blocked by cloudflare - we probably need some kind of external service or undetected-chromedriver for this...
        # {'type': 'html', 'src': 'https://10minutemail.com/session/address', 'regex': re.compile(r""".+?@?([a-z0-9\.-]{1,128})""", re.I)},
        {'type': 'html', 'src': 'https://correotemporal.org', 'regex': DOMAIN_SEARCH_RE},
        {'type': 'html', 'src': 'https://www.temporary-mail.net',
            'regex': re.compile(r"""<a.+?data-mailhost=\"@?([a-z0-9\.-]{1,128})\"""", re.I)},
        {'type': 'html', 'src': 'https://nospam.today/home', 'regex': [
            re.compile(r"""wire:initial-data="(.+?domains[^\"]+)\""""),
            re.compile(r"""\&quot;domains\&quot;:\[([^\]]+)\]"""),
            re.compile(r"""\&quot;([^\&]+)\&quot;""")
        ]},
        {'type': 'html', 'src': 'https://www.luxusmail.org',
            'regex': re.compile(r"""<a.+?domain-selector\"[^>]+>@([a-z0-9\.-]{1,128})""", re.I)},
        {'type': 'html', 'src': 'https://lortemail.dk'},
        {'type': 'html', 'src': 'https://tempmail.plus/en/',
            'regex': re.compile(r"""<button type=\"button\" class=\"dropdown-item\">([^<]+)</button>""", re.I)},
        {'type': 'html', 'src': 'https://spamok.nl/demo' + generate_random_string(8),
            'regex': re.compile(r"""<option\s+value="([^"]+)">""", re.I)},
        {'type': 'html', 'src': 'https://tempr.email',
            'regex': re.compile(r"""<option\s+value[^>]*>@?([a-z0-9\-\.\&#;\d+]+)\s*(\(PW\))?<\/option>""", re.I)},
        {'type': 'ws', 'src': 'wss://dropmail.me/websocket'},
        {'type': 'custom', 'src': 'Tempmailo', 'scrape': True}
    ]

    def __init__(self, options: Optional[Dict[str, Union[str, bool]]] = None, out_file: Optional[str] = None):
        """
        Initializes a DisposableGenerator object.

        Args:
            options (Optional[Dict[str, Union[str, bool]]]): A dictionary of options to configure the generator.
            out_file (Optional[str]): Path to the output file. If not specified, defaults to 'domains'.
        """

        self.options = options or {}

        if not self.options.get('skip_src'):
            self.options['skip_src'] = []

        log_level = logging.INFO if self.options.get('verbose') else logging.WARN
        if self.options.get('debug'):
            log_level = logging.DEBUG
        logging.basicConfig(format="%(levelname)s: %(message)s", level=log_level)

        logger = logging.getLogger('tldextract')
        logger.setLevel('WARNING')

        self.domains = set()
        self.legacy_domains = set()
        self.no_mx = set()
        self.old_domains = set()
        self.old_sha1 = set()
        self.out_file = 'domains' if out_file is None else out_file
        self.scrape = set()
        self.sha1 = set()
        self.skip = set()
        self.grey = set()
        self.source_map = {}

        if self.options.get('file'):
            self.sources.insert(0, {
                'type': 'file',
                'src': self.options['file']
            })

        # load remote URL if no custom list is defined
        if self.options.get('whitelist') is None:
            self.sources.insert(0, {
                'type': 'whitelist',
                'src': DISPOSABLE_WHITELIST_URL
            })
            self.options['whitelist'] = 'whitelist.txt'
        else:
            self.sources.insert(0, {
                'type': 'whitelist_file',
                'src': self.options.get('whitelist'),
                'ignore_not_exists': self.options.get('whitelist') == 'whitelist.txt'
            })

        if self.options.get('greylist') is None:
            self.sources.insert(0, {
                'type': 'greylist',
                'src': DISPOSABLE_GREYLIST_URL
            })
        else:
            self.sources.insert(0, {
                'type': 'greylist_file',
                'src': self.options.get('greylist'),
                'ignore_not_exists': self.options.get('greylist') == 'greylist.txt'
            })

    def _fetch_data(self, source: Dict[str, Any]) -> bytes:
        """
        Fetches data from the specified source.

        Args:
            source (Dict[str, Any]): A dictionary containing the source information.

        Returns:
            bytes: The fetched data.
        """
        if source.get('type') in ('file', 'whitelist_file', 'greylist_file'):
            return remoteData.fetch_file(source['src'], source.get('ignore_not_exists', False))
        elif source.get('type') == 'custom':
            return getattr(self, f"_process{source['src']}")()
        elif source.get('type') == 'ws':
            return remoteData.fetch_ws(source['src'])

        headers = {}
        if source.get('type') == 'json':
            headers['Accept'] = 'application/json, text/javascript, */*; q=0.01'
            headers['X-Requested-With'] = 'XMLHttpRequest'
        return remoteData.fetch_http(source['src'], headers, source.get('timeout', 3), int(self.options.get('max_retry', 1)))

    def _preprocess_json(self, source: Dict[str, Any], data: bytes) -> Optional[List[str]]:
        """
        Preprocesses JSON data.

        Args:
            source (Dict[str, Any]): A dictionary containing the source information.
            data (bytes): The data to preprocess.

        Returns:
            Union[list, bool]: The preprocessed data, or False if the data is invalid.
        """

        raw = {}
        try:
            raw = json.loads(data.decode(source.get('encoding', 'utf-8')))
        except Exception as e:
            if 'Unexpected UTF-8 BOM' in str(e):
                raw = json.loads(data.decode('utf-8-sig'))

        if not raw:
            logging.warning('No data in json')
            return

        if 'domains' in raw:
            raw = raw['domains']

        if 'email' in raw:
            s = re.search(r'^.+?@?([a-z0-9\.-]{1,128})$', raw['email'])
            if s:
                raw = [s[1]]

        if not isinstance(raw, list):
            logging.warning('This URL does not contain a JSON array')
            return
        return list(filter(lambda line: line and isinstance(line, str), raw))

    def _preprocess_file(self, source: Dict[str, Any], data: bytes) -> List[str]:
        """
        Preprocesses file data.

        Args:
            source (Dict[str, Any]): A dictionary containing the source information.
            data (bytes): The data to preprocess.

        Returns:
            Union[list, bool]: The preprocessed data, or False if the data is invalid.
        """
        lines = []
        for line in data.splitlines():
            line = line.decode(source.get('encoding', 'utf-8')).strip()
            if line.startswith('#') or line == '':
                continue
            lines.append(line)
        return lines

    def _preprocess_html(self, source: Dict[str, Any], data: bytes) -> List[str]:
        """
        Preprocesses HTML data.

        Args:
            source (Dict[str, Any]): A dictionary containing the source information.
            data (bytes): The data to preprocess.

        Returns:
            Union[list, bool]: The preprocessed data, or False if the data is invalid.
        """
        raw = data.decode(source.get('encoding', 'utf-8'))
        html_re = source.get('regex', HTML_GENERIC_RE)
        if type(html_re) is not list:
            html_re = [html_re, ]

        html_ipt = raw
        html_list = []
        for html_re_item in html_re:
            html_list = html_re_item.findall(html_ipt)
            html_ipt = '\n'.join(list(map(lambda o: o[0] if type(o) is tuple else o, html_list)))

        return list(map(lambda opt: html.unescape(opt[0]) if type(opt) is tuple else opt, html_list))

    def _preprocess_sha1(self, data: bytes):
        """
        Preprocesses SHA1 data.

        Args:
            data (bytes): The data to preprocess.
        """
        x = 0
        for sha1_str in [line.decode('ascii').lower() for line in data.splitlines()]:
            if not sha1_str or not SHA1_RE.match(sha1_str):
                continue

            x += 1
            self.sha1.add(sha1_str)

        if x < 1:
            logging.warning('SHA1 source did not return any valid sha1 hash')

    def _preprocess_data(self, source: Dict[str, Any], data: bytes) -> Optional[List[str]]:
        """
        Preprocesses the given data based on the specified format in the source dictionary.

        Args:
            source (Dict[str, Any]): A dictionary containing metadata about the data format.
            data (Union[list, bytes]): The data to preprocess.

        Returns:
            Optional[List[str]]: A list of preprocessed strings, or None if the data format is not recognized / supported.
        """
        if type(data) is list:
            return data

        fmt = source['type']
        if fmt == 'json':
            return self._preprocess_json(source, data)

        if fmt in ('whitelist', 'list', 'file', 'whitelist_file', 'greylist', 'greylist_file'):
            return self._preprocess_file(source, data)

        if fmt == 'html':
            return self._preprocess_html(source, data)

        if fmt == 'sha1':
            self._preprocess_sha1(data)
            return []

        if fmt == 'ws':
            for line in data.splitlines():
                line = line.decode('utf-8')
                if line[0] == 'D':
                    return line[1:].split(',')

    def _postprocess_data(self, source: Dict[str, Any], data: bytes, lines: List[str]) -> Union[bool, Tuple[int, int]]:
        """
        Post processes the data obtained from a source.

        Args:
            source (Dict[str, Any]): The source of the data.
            data (bytes): The data obtained from the source.
            lines (List[str]): The lines of the data.

        Returns:
            Union[bool, Tuple[int, int]]: Returns True if the source is whitelisted, False if no results were found,
            or a tuple containing the number of added domains and the total number of lines filtered.
        """
        lines_filtered = [line.lower().strip(' .,;@') for line in lines]
        lines_filtered = list(filter(lambda line: self.check_valid_domains(line), lines_filtered)) or DOMAIN_SEARCH_RE.findall(str(data))

        if source['type'] in ('whitelist', 'whitelist_file', 'sha1'):
            for host in lines_filtered:
                self.skip.add(host)
            return True

        if source['type'] in ('greylist', 'greylist_file'):
            for host in lines_filtered:
                self.grey.add(host)
            return True

        if not lines_filtered:
            logging.warning('No results for source %s', source)
            return False

        self.source_map[source['src']] = self.scrape if source.get('scrape') else lines_filtered

        added_domains = 0
        added_scrape_domains = []
        for host in lines_filtered:
            if host not in self.domains:
                self.domains.add(host)
                added_domains += 1

            self.legacy_domains.add(host)

            try:
                self.sha1.add(hashlib.sha1(host.encode('idna')).hexdigest())
            except Exception:
                pass

            if source.get('scrape') and host not in self.scrape:
                self.scrape.add(host)
                added_scrape_domains.append(host)

        if lines_filtered:
            logging.debug("Example domain: %s", lines_filtered[0])

        if source.get('scrape'):
            logging.info('Added %s scraped domains: %s', len(added_scrape_domains), added_scrape_domains)
            return len(added_scrape_domains), len(lines_filtered)

        return added_domains, len(lines_filtered)

    def process(self, source: Dict[str, Any]) -> bool:
        """
        Process the given source and generate disposable data.

        Args:
            source (Dict[str, Any]): A dictionary containing the source information.

        Returns:
            bool: True if the process was successful, False otherwise.
        """
        logging.info("Process %s (%s)", source['src'], source['type'])
        if self.options.get('skip_scrape') and source.get('scrape'):
            logging.info('Skipping scraping source %s', source['src'])
            source['scrape'] = False

        max_scrape = 80
        scrape_max_retry = 3
        scrape_count = 0
        self.scrape = set()
        scrape_retry = 0

        while scrape_count < max_scrape:
            data = self._fetch_data(source)
            if data is None:
                logging.warning("No results by %s", source['src'])
                return False

            logging.debug("Fetched %s bytes", len(data))
            lines = self._preprocess_data(source, data)
            if lines is None:
                return False

            res = self._postprocess_data(source, data, lines)
            if type(res) is bool:
                return res

            (processed_entries, found_entries) = res

            logging.debug('Processed %s entries (%s found)', processed_entries, found_entries)
            if source.get('scrape'):
                if processed_entries:
                    scrape_retry = 0
                else:
                    scrape_retry += 1
                    if scrape_retry > scrape_max_retry:
                        return True
                time.sleep(source.get('timeout', 8))
                continue
            return True
        return False

    def _processTempmailo(self) -> Optional[List[str]]:
        """
        Fetches a list of disposable email domains from tempmailo.com.

        Returns:
            A list of strings representing disposable email domains, or None if the request fails.
        """
        res = remoteData.fetch_http_raw('https://tempmailo.com/')
        if res is None:
            return None

        cookies = {}
        for (ky, vl) in res.headers.items():
            if ky.lower() != 'set-cookie':
                continue

            (ck_name, ck_data) = vl.split('=', 1)
            if ck_name.startswith('__'):
                continue
            (ck_value, _) = ck_data.split(';', 1)
            cookies[ck_name] = ck_value

        body = res.read().decode('utf8')

        f = re.search('name="__RequestVerificationToken".+?value="([^"]+)"', body)
        if not f:
            logging.warning('Failed to fetch __RequestVerificationToken')
            return None

        headers = {
            'requestverificationtoken': f[1],
            'accept': 'application/json, text/plain, */*',
            'x-requested-with': 'XMLHttpRequest',
            'referer': 'https://tempmailo.com/',
            'cookie': '; '.join([f'{ky}={vl}' for ky, vl in cookies.items()]),
        }

        data = remoteData.fetch_http('https://tempmailo.com/changemail', headers=headers)
        if not data:
            logging.warning('Failed to fetch https://tempmailo.com/changemail endpoint')
            return None

        lines = []
        for line in data.splitlines():
            (_, domain) = line.decode('utf8').split('@', 1)
            lines.append(domain)

        return lines

    def read_files(self):
        """ read and compare to current (old) domains file
        """
        self.old_domains = set()
        try:
            with open(f'{self.out_file}.txt') as f:
                for line in f:
                    self.old_domains.add(line.strip())
        except IOError:
            pass

        self.old_sha1 = set()
        try:
            with open(f'{self.out_file}_sha1.txt') as f:
                for line in f:
                    self.old_sha1.add(line.strip())
        except IOError:
            pass

        self.legacy_domains = set()
        try:
            with open(f'{self.out_file}_legacy.txt') as f:
                for line in f:
                    self.legacy_domains.add(line.strip())
        except IOError:
            pass

    def check_valid_domains(self, host: str) -> bool:
        """Check if the given host is a valid domain name.

        Args:
            host (str): The host to check.

        Returns:
            bool: True if the host is a valid domain name, False otherwise.
        """
        try:
            if not DOMAIN_RE.match(host):
                return False

            t = tldextract.extract(host)
            return (t.domain != '' and t.suffix != '')
        except Exception:
            pass

        return False

    @staticmethod
    @functools.lru_cache(maxsize=1024 * 1024)
    def resolve_DNS(resolver: dns.resolver.Resolver,
                    host: str,
                    rdtype: Any) -> Optional[Union[str, dns.resolver.Answer]]:
        """
        Resolve the given hostname against the given resolver and return the result or error.

        Args:
            resolver (dns.resolver.Resolver): The DNS resolver to use for the query.
            host (str): The hostname to resolve.
            rdtype (dns.rdatatype.RdataType): The type of DNS record to query for.

        Returns:
            Optional[Union[str, dns.resolver.Answer]]: The result of the DNS query, or an error message if the query failed.
        """
        r = None
        try:
            r = resolver.query(host, rdtype)
        except KeyboardInterrupt:
            raise
        except dns.resolver.NXDOMAIN:
            return 'resolved but no entry'
        except dns.resolver.NoNameservers:
            return 'answer refused'
        except dns.resolver.NoAnswer:
            return 'no answer section'
        except dns.exception.Timeout:
            return 'timeout'
        except Exception:
            pass

        return r

    @staticmethod
    def fetch_MX(domain: str,
                 nameservers: Optional[List[str]] = None,
                 dnsport: Optional[int] = None,
                 resolver_timeout: Optional[int] = None) -> Tuple[str, bool]:
        """
        Check if given domain has a valid MX entry.

        Args:
            domain (str): The domain to check for MX entry.
            nameservers (Optional[List[str]], optional): List of nameservers to use for DNS resolution. Defaults to None.
            dnsport (Optional[int], optional): The port to use for DNS resolution. Defaults to 53.
            resolver_timeout (Optional[int], optional): The timeout for DNS resolution. Defaults to 20.

        Returns:
            Tuple[str, bool]: A tuple containing the domain and a boolean value indicating if it has a valid MX entry.
        """
        if resolver_timeout is None:
            resolver_timeout = 20

        resolver = dns.resolver.Resolver()
        resolver.lifetime = resolver.timeout = resolver_timeout

        if nameservers:
            resolver.nameservers = nameservers

        if dnsport:
            resolver.port = dnsport

        rq = [(domain, dns.rdatatype.MX, 'MX'), ]

        while rq:
            resolve = rq.pop()
            r = disposableHostGenerator.resolve_DNS(resolver, resolve[0], resolve[1])

            if type(r) is str:
                logging.debug("%20s: resolved %20s (%2s): %s", domain, resolve[0], resolve[2], r)
                r = None

            if resolve[1] == dns.rdatatype.MX:
                mx_list = []
                if r:
                    mx_list = {rr.exchange.to_text(rr.exchange).lower() for rr in r.rrset}

                logging.debug("%20s: resolved %20s (%2s): %s", domain, resolve[0], resolve[2], mx_list)
                if mx_list:
                    if ('.' in mx_list or mx_list == ['localhost']):
                        return (domain, False)

                    rq.extend((x, dns.rdatatype.A, 'A') for x in mx_list)
                else:
                    rq.append((domain, dns.rdatatype.A, 'A'))
                continue

            if not r:
                continue

            invalid_ip = False
            ips = []
            for _r in r:
                _ipr = None
                try:
                    ips.append(_r.address)
                    _ipr = ipaddress.ip_address(_r.address)
                except Exception:
                    invalid_ip = True
                    break

                if not _ipr or _ipr.is_private or _ipr.is_reserved or _ipr.is_loopback or _ipr.is_multicast:
                    invalid_ip = True
                    break

            logging.debug("%20s: resolved %20s (%2s): %s (invalid: %s)", domain, resolve[0], resolve[2], ips, invalid_ip)

            if not invalid_ip:
                return (domain, True)

        return (domain, False)

    def list_sources(self):
        """list all available sources
        """
        for source in self.sources:
            logging.info("Source %12s: %s", source.get('type'), source.get('src'))

    def add_greylist(self):
        """add greylist to domains + sha1
        """
        self.domains.update(self.grey)
        for host in self.grey:
            try:
                self.sha1.add(hashlib.sha1(host.encode('idna')).hexdigest())
            except Exception:
                pass
        self.source_map['greylist'] = self.grey

    def generate(self):
        """Fetch all data + generate lists
        """
        # fetch data from sources
        for source in self.sources:
            if (source['src'] not in ('whitelist_file', 'greylist_file') and
                    self.options.get('src_filter') is not None and
                    source['src'] != self.options.get('src_filter')) or source['src'] in self.options['skip_src']:
                continue

            try:
                if not self.process(source) and self.options.get('debug'):
                    raise RuntimeError(f"No result for {source}")
            except Exception as err:
                logging.exception(err)
                raise err

        skip = self.skip.copy()
        if self.options.get('strict'):
            skip.update(self.grey)

        # remove all domains listed in whitelist from result set
        for domain in skip:
            try:
                self.domains.remove(domain)
            except KeyError:
                pass

            try:
                self.sha1.remove(hashlib.sha1(domain.encode('idna')).hexdigest())
            except KeyError:
                pass

            if self.options.get('dns_verify') and domain not in ('example.com', 'example.org', 'example.net'):
                r = disposableHostGenerator.fetch_MX(domain,
                                                     self.options.get('nameservers'),
                                                     self.options.get('dnsport'),
                                                     self.options.get('dns_timeout', 20)
                                                     )
                if not r or not r[1]:
                    logging.warning('Skipped domain %s does not resolve!', domain)

        # MX verify check
        self.no_mx = []
        if self.options.get('dns_verify'):
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.options.get('dns_threads', 1)) as executor:
                futures = [executor.submit(disposableHostGenerator.fetch_MX, domain,
                                           self.options.get('nameservers'), self.options.get('dnsport'), self.options.get('dns_timeout', 20))
                           for domain in self.domains]
                for future in concurrent.futures.as_completed(futures):
                    (domain, valid) = future.result()
                    if not valid:
                        self.no_mx.append(domain)

        if self.options.get('verbose'):
            if not self.old_domains:
                self.read_files()

            added = list(
                filter(lambda domain: domain not in self.old_domains, self.domains))
            removed = list(
                filter(lambda domain: domain not in self.domains, self.old_domains))

            added_sha1 = list(
                filter(lambda sha_str: sha_str not in self.old_sha1, self.sha1))
            removed_sha1 = list(
                filter(lambda sha_str: sha_str not in self.sha1, self.old_sha1))

            logging.info('Fetched %s domains and %s hashes', len(self.domains), len(self.sha1))
            if self.options.get('dns_verify'):
                logging.info(' - %s domain(s) have no MX', len(self.no_mx))
                if self.options.get('list_no_mx'):
                    logging.info('No MX: %s', self.no_mx)
            logging.info(' - %s domain(s) added', len(added))
            logging.info(' - %s domain(s) removed', len(removed))
            logging.info(' - %s hash(es) added', len(added_sha1))
            logging.info(' - %s hash(es) removed', len(removed_sha1))
            # stop if nothing has changed
            if len(added) == len(removed) == len(added_sha1) == len(removed_sha1) == 0:
                return False

            if self.options.get('src_filter'):
                logging.info("Fetched: %s", self.domains)

        return True

    def write_to_file(self):
        """write new list to file(s)
        """
        domains = sorted(self.domains)
        with open(f'{self.out_file}.txt', 'w') as ff:
            ff.write('\n'.join(domains))

        with open(f'{self.out_file}.json', 'w') as ff:
            ff.write(json.dumps(domains))

        if self.options.get('source_map'):
            with open(f'{self.out_file}_source_map.txt', 'w') as ff:
                for (src_url, source_map_domains) in sorted(self.source_map.items()):
                    ff.write(f'{src_url}:' + ('\n%s:' % src_url).join(sorted(source_map_domains)) + "\n")

        if self.no_mx:
            domains_with_mx = self.domains
            for domain in self.no_mx:
                try:
                    domains_with_mx.remove(domain)
                except KeyError:
                    pass

            domains = sorted(domains_with_mx)
            with open(f'{self.out_file}_mx.txt', 'w') as ff:
                ff.write('\n'.join(domains))

            with open(f'{self.out_file}_mx.json', 'w') as ff:
                ff.write(json.dumps(domains))

        # write new hash list to file(s)
        domains_sha1 = sorted(self.sha1)
        with open(f'{self.out_file}_sha1.txt', 'w') as ff:
            ff.write('\n'.join(domains_sha1))

        with open(f'{self.out_file}_sha1.json', 'w') as ff:
            ff.write(json.dumps(domains_sha1))


def main():
    exit_status = 1
    parser = argparse.ArgumentParser(description='Generate list of disposable mail hosts.')
    parser.add_argument('--dns-verify', action='store_true', dest='dns_verify',
                        help='validate if valid MX / A record is present for hosts')
    parser.add_argument('--source-map', action='store_true', dest='source_map', help='generate source map')
    parser.add_argument('--src', dest='src_filter', help='only request entries for given source')
    parser.add_argument('-q', '--quiet', action='store_false', dest='verbose', help='hide verbose output')
    parser.add_argument('-D', '--debug', action='store_true', dest='debug', help='show debug output and exit on warn/error')
    parser.add_argument('--max-retry', type=int, dest='max_retry',
                        help='maximum count of retries to fetch an url, default: 150', default=150)
    parser.add_argument('--dns-threads', type=int, dest='dns_threads',
                        help='count of threads to use for dns resolving, default:10', default=10)
    parser.add_argument('--dns-timeout', type=int, dest="dns_timeout", help='timeout for dns request, default: 20', default=20.0)
    parser.add_argument('--ns', action='append', dest='nameservers', help='set custom resolver for dns-verify')
    parser.add_argument('--dnsport', type=int, dest='dnsport', help='set custom resolver port for dns-verify')
    parser.add_argument('--list-sources', action='store_true', dest='list_sources', help='list all sources')
    parser.add_argument('--list-no-mx', action='store_true', dest='list_no_mx', help='list domains without valid mx')
    parser.add_argument('--whitelist', dest='whitelist',
                        help='custom whitelist to load - all domains listed in that file are removed from output')
    parser.add_argument('--greylist', dest='greylist',
                        help='custom greylist to load - all domains listed in that file are removed from output if not --strict is set')
    parser.add_argument('--file', dest='file', help='custom file to load - add custom domains to local result')
    parser.add_argument('--skip-scrape', dest='skip_scrape', action='store_true', help='skip domain scraping - only use static sources')
    parser.add_argument('--skip-src', dest='skip_src', action='append', help='skip given src - can be set multiple times')
    parser.add_argument('--strict', dest='strict', action="store_true", help='remove domains with anonymous signup methods - see greylist.txt')
    parser.add_argument('--dedicated-strict', dest='dedicated_strict', action="store_true", help='create additional file including domains skipped in strict mode')

    options = parser.parse_args()
    dhg = disposableHostGenerator(vars(options))
    if options.list_sources:
        dhg.list_sources()
    elif dhg.generate() or options.src_filter is not None:
        exit_status = 0
        dhg.write_to_file()
        if options.dedicated_strict:
            dhg.add_greylist()
            dhg.out_file = 'domains_strict'
            dhg.write_to_file()
    sys.exit(exit_status)


if __name__ == '__main__':
    main()
