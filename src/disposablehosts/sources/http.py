"""HTTP source handling for web-based sources."""

from typing import Dict, Optional

import httpx

from ..remote_data import remoteData


def fetch_http_source(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[int] = None,
    max_retry: Optional[int] = None,
) -> bytes:
    """Fetch data from an HTTP/HTTPS source.

    Args:
        url: The URL to fetch.
        headers: Optional headers to include.
        timeout: Request timeout in seconds.
        max_retry: Maximum retry attempts.

    Returns:
        Response content as bytes.
    """
    return remoteData.fetch_http(url, headers, timeout, max_retry)


def fetch_http_source_raw(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[int] = None,
    max_retry: Optional[int] = None,
) -> Optional[httpx.Response]:
    """Fetch raw HTTP response from a source.

    Args:
        url: The URL to fetch.
        headers: Optional headers to include.
        timeout: Request timeout in seconds.
        max_retry: Maximum retry attempts.

    Returns:
        Raw HTTP response object or None if failed.
    """
    return remoteData.fetch_http_raw(url, headers, timeout, max_retry)
