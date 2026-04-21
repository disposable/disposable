"""DNS resolution and MX validation utilities."""

import functools
import ipaddress
import logging
from typing import Any, List, Optional, Tuple, Union

import dns.exception
import dns.rdatatype
import dns.resolver


@functools.lru_cache(maxsize=1024 * 1024)
def resolve_DNS_cached(
    host: str,
    rdtype: Any,
    nameserver_tuple: Optional[tuple] = None,
) -> Optional[Union[str, dns.resolver.Answer]]:
    """Resolve the given hostname (cached version).

    Args:
        host: The hostname to resolve.
        rdtype: The type of DNS record to query for.
        nameserver_tuple: Optional tuple of (nameservers, port, timeout) for cache key.

    Returns:
        The result of the DNS query, or an error message string if the query failed.
    """
    resolver = dns.resolver.Resolver()
    if nameserver_tuple:
        nameservers, port, timeout = nameserver_tuple
        if nameservers:
            resolver.nameservers = nameservers
        if port:
            resolver.port = port
        if timeout:
            resolver.lifetime = resolver.timeout = timeout

    r = None
    try:
        r = resolver.resolve(host, rdtype)
    except KeyboardInterrupt:
        raise
    except dns.resolver.NXDOMAIN:
        return "resolved but no entry"
    except dns.resolver.NoNameservers:
        return "answer refused"
    except dns.resolver.NoAnswer:
        return "no answer section"
    except dns.exception.Timeout:
        return "timeout"
    except Exception:  # nosec B110 - Generic exception handler for DNS resolution failures
        pass

    return r


def _process_mx_resolution(
    domain: str,
    resolve: Tuple[str, Any, str],
    cache_key: Tuple,
) -> Tuple[Optional[set], bool]:
    """Process MX resolution and return MX list or None.

    Returns:
        Tuple of (mx_list, is_invalid) where mx_list is None if not MX record.
    """
    r = resolve_DNS_cached(resolve[0], resolve[1], cache_key)

    if isinstance(r, str):
        logging.debug("%20s: resolved %20s (%2s): %s", domain, resolve[0], resolve[2], r)
        return (None, False)

    if resolve[1] != dns.rdatatype.MX:
        return (None, False)

    mx_list = set()
    if r and r.rrset:
        mx_list = {rr.exchange.to_text(rr.exchange).lower() for rr in r.rrset}

    logging.debug("%20s: resolved %20s (%2s): %s", domain, resolve[0], resolve[2], mx_list)

    if not mx_list:
        return (set(), False)

    if "." in mx_list or "localhost" in mx_list:
        return (mx_list, True)

    return (mx_list, False)


def _validate_ip_addresses(r: Any) -> Tuple[bool, List[str]]:
    """Validate IP addresses from DNS response.

    Returns:
        Tuple of (is_invalid, ip_list).
    """
    invalid_ip = False
    ips = []
    for _r in r:
        _ipr = None
        try:
            ips.append(_r.address)
            _ipr = ipaddress.ip_address(_r.address)
        except Exception:  # nosec B110 - Generic exception handler for DNS resolution failures
            invalid_ip = True
            break

        if not _ipr or _ipr.is_private or _ipr.is_reserved or _ipr.is_loopback or _ipr.is_multicast:
            invalid_ip = True
            break

    return (invalid_ip, ips)


def fetch_MX(
    domain: str,
    nameservers: Optional[List[str]] = None,
    dnsport: Optional[int] = None,
    resolver_timeout: Optional[int] = None,
) -> Tuple[str, bool]:
    """Check if given domain has a valid MX entry.

    Args:
        domain: The domain to check for MX entry.
        nameservers: List of nameservers to use for DNS resolution.
        dnsport: The port to use for DNS resolution.
        resolver_timeout: The timeout for DNS resolution.

    Returns:
        A tuple containing the domain and a boolean indicating if it has a valid MX entry.
    """
    if resolver_timeout is None:
        resolver_timeout = 20

    rq = [(domain, dns.rdatatype.MX, "MX")]
    cache_key = (tuple(nameservers) if nameservers else None, dnsport, resolver_timeout)

    while rq:
        resolve = rq.pop()

        # Handle MX records
        if resolve[1] == dns.rdatatype.MX:
            mx_list, is_invalid = _process_mx_resolution(domain, resolve, cache_key)
            if is_invalid:
                return (domain, False)
            if mx_list is not None:
                if mx_list:
                    rq.extend((x, dns.rdatatype.A, "A") for x in mx_list)
                else:
                    rq.append((domain, dns.rdatatype.A, "A"))
                continue

        # Handle A/AAAA records
        r = resolve_DNS_cached(resolve[0], resolve[1], cache_key)
        if isinstance(r, str) or not r:
            continue

        invalid_ip, ips = _validate_ip_addresses(r)
        logging.debug(
            "%20s: resolved %20s (%2s): %s (invalid: %s)",
            domain,
            resolve[0],
            resolve[2],
            ips,
            invalid_ip,
        )

        if not invalid_ip:
            return (domain, True)

    return (domain, False)
