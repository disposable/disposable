"""DNS resolution and MX validation utilities."""

import functools
import ipaddress
import logging
from typing import Any, List, Optional, Tuple, Union

import dns.exception
import dns.rdatatype
import dns.resolver


@functools.lru_cache(maxsize=1024 * 1024)
def resolve_DNS(
    resolver: dns.resolver.Resolver,
    host: str,
    rdtype: Any,
) -> Optional[Union[str, dns.resolver.Answer]]:
    """Resolve the given hostname against the given resolver.

    Args:
        resolver: The DNS resolver to use for the query.
        host: The hostname to resolve.
        rdtype: The type of DNS record to query for.

    Returns:
        The result of the DNS query, or an error message string if the query failed.
    """
    r = None
    try:
        r = resolver.query(host, rdtype)
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

    resolver = dns.resolver.Resolver()
    resolver.lifetime = resolver.timeout = resolver_timeout

    if nameservers:
        resolver.nameservers = nameservers

    if dnsport:
        resolver.port = dnsport

    rq = [(domain, dns.rdatatype.MX, "MX")]

    while rq:
        resolve = rq.pop()
        r = resolve_DNS(resolver, resolve[0], resolve[1])

        if isinstance(r, str):
            logging.debug("%20s: resolved %20s (%2s): %s", domain, resolve[0], resolve[2], r)
            r = None

        if resolve[1] == dns.rdatatype.MX:
            mx_list = set()
            if r and r.rrset:
                mx_list = {rr.exchange.to_text(rr.exchange).lower() for rr in r.rrset}

            logging.debug("%20s: resolved %20s (%2s): %s", domain, resolve[0], resolve[2], mx_list)
            if mx_list:
                if "." in mx_list or mx_list == ["localhost"]:
                    return (domain, False)

                rq.extend((x, dns.rdatatype.A, "A") for x in mx_list)
            else:
                rq.append((domain, dns.rdatatype.A, "A"))
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
            except Exception:  # nosec B110 - Generic exception handler for DNS resolution failures
                invalid_ip = True
                break

            if not _ipr or _ipr.is_private or _ipr.is_reserved or _ipr.is_loopback or _ipr.is_multicast:
                invalid_ip = True
                break

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
