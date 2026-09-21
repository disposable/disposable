"""Remote data fetching utilities."""

import logging
import os
import time
from typing import Any, Dict, Optional

import httpx
from websocket import create_connection

from .constants import RETRY_ERRORS_RE


class remoteData:
    """Static utility class for fetching data from various sources."""

    @staticmethod
    def fetch_file(src: str, ignore_errors: Optional[bool] = False) -> bytes:
        """Read the contents of a file and return it as bytes.

        Args:
            src: The path to the file to read.
            ignore_errors: Whether to ignore errors if the file is not found.

        Returns:
            The contents of the file as bytes.

        Raises:
            FileNotFoundError: If the file is not found and ignore_errors is False.
            IOError: If there is an error reading the file and ignore_errors is False.
        """
        try:
            with open(src, "rb") as f:
                return f.read()
        except (FileNotFoundError, IOError) as e:
            if ignore_errors:
                return b""
            raise e

    @staticmethod
    def fetch_ws(src: str) -> bytes:
        """Fetch data from a WebSocket connection (first 3 messages).

        Args:
            src: The WebSocket URL to connect to.

        Returns:
            The data received from the WebSocket connection.
        """
        try:
            ws = create_connection(src)
            data = []
            for _ in range(3):
                line = ws.recv()
                if isinstance(line, str):
                    line = line.encode("utf-8")
                data.append(line)
            ws.close()
        except Exception as e:
            logging.warning("WebSocket connection failed: %s", e)
            return b""

        return b"\n".join(data)

    @staticmethod
    def fetch_http_raw(
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        max_retry: Optional[int] = None,
    ) -> Optional[httpx.Response]:
        """Fetch the raw HTTP response for a given URL.

        Args:
            url: The URL to fetch.
            headers: Optional headers to include in the request.
            timeout: Optional timeout for the request in seconds.
            max_retry: Optional maximum number of retries if the request fails.

        Returns:
            The HTTP response, or None if the request failed.
        """
        if not headers:
            headers = {}

        if timeout is None:
            timeout = 3

        if max_retry is None:
            max_retry = 150

        retry = 0
        headers.setdefault(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/118.0",
        )
        headers.setdefault(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        )
        with httpx.Client(http2=True, verify=False) as client:  # nosec B501 - Required for scraping various email services with self-signed certs
            while retry < max_retry:
                try:
                    return client.get(url, headers=headers, timeout=timeout)
                except Exception as e:
                    retry += 1
                    logging.error(e)
                    if RETRY_ERRORS_RE.search(str(e)) and retry < max_retry:
                        time.sleep(1)
                        continue

                    logging.warning("Fetching URL %s failed, see error: %s", url, e)
                    break
        return None

    @staticmethod
    def fetch_http(
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        max_retry: Optional[int] = None,
    ) -> bytes:
        """Fetch the content of a given URL using HTTP GET method.

        Calls fetch_http_raw and returns the content of the response as bytes
        if the request was successful.

        Args:
            url: The URL to fetch.
            headers: Optional headers to include in the request.
            timeout: Optional timeout for the request in seconds.
            max_retry: Optional maximum number of retries if the request fails.

        Returns:
            The content of the response as bytes.
        """
        res = remoteData.fetch_http_raw(url, headers, timeout, max_retry)
        body = (res and res.read()) or b""
        if remoteData._is_cloudflare_challenge(res, body) and os.environ.get("FLARESOLVERR_URL"):
            logging.info("Cloudflare challenge detected for %s, retrying via FlareSolverr", url)
            return remoteData.fetch_flaresolverr(url)
        return body

    @staticmethod
    def _is_cloudflare_challenge(res: Optional[httpx.Response], body: bytes) -> bool:
        """Check whether a response is a Cloudflare challenge page."""
        if res is None or getattr(res, "status_code", None) not in (403, 503):
            return False
        return b"cdn-cgi/challenge-platform" in body or b"Just a moment" in body

    @staticmethod
    def fetch_flaresolverr(url: str, timeout: int = 60, post_data: Optional[str] = None) -> bytes:
        """Fetch a URL via a FlareSolverr instance to bypass JS challenges.

        Requires the FLARESOLVERR_URL environment variable to point to a
        running FlareSolverr instance (e.g. http://127.0.0.1:8191).

        Args:
            url: The URL to fetch.
            timeout: Timeout in seconds for the challenge solving.
            post_data: Optional form-encoded body; uses request.post when set.

        Returns:
            The solved response body as bytes, or b"" on failure.
        """
        flaresolverr_url = os.environ.get("FLARESOLVERR_URL", "").rstrip("/")
        if not flaresolverr_url:
            return b""
        payload: Dict[str, Any] = {"cmd": "request.post" if post_data is not None else "request.get", "url": url, "maxTimeout": timeout * 1000}
        if post_data is not None:
            payload["postData"] = post_data
        try:
            res = httpx.post(f"{flaresolverr_url}/v1", json=payload, timeout=timeout + 15).json()
            solution = res.get("solution") or {}
            if res.get("status") == "ok" and solution.get("status") == 200:
                return str(solution.get("response") or "").encode("utf-8")
            logging.warning("FlareSolverr failed for %s: %s", url, res.get("message"))
        except Exception as e:
            logging.warning("FlareSolverr request for %s failed: %s", url, e)
        return b""

    @staticmethod
    def fetch_http_post(
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        max_retry: Optional[int] = None,
    ) -> bytes:
        """Send an HTTP POST request and return the response body as bytes.

        Args:
            url: The URL to POST to.
            headers: Optional headers to include in the request.
            data: Optional form data to send in the request body.
            json_data: Optional JSON data to send in the request body.
            timeout: Optional timeout for the request in seconds.
            max_retry: Optional maximum number of retries if the request fails.

        Returns:
            The content of the response as bytes.
        """
        if not headers:
            headers = {}

        if timeout is None:
            timeout = 3

        if max_retry is None:
            max_retry = 5

        headers.setdefault(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/118.0",
        )
        headers.setdefault("Accept", "application/json, text/plain, */*")

        retry = 0
        with httpx.Client(http2=True, verify=False) as client:  # nosec B501 - Required for scraping various email services with self-signed certs
            while retry < max_retry:
                try:
                    res = client.post(url, headers=headers, timeout=timeout, data=data, json=json_data)
                    return res.read()
                except Exception as e:
                    retry += 1
                    logging.error(e)
                    if RETRY_ERRORS_RE.search(str(e)) and retry < max_retry:
                        time.sleep(1)
                        continue

                    logging.warning("POST %s failed, see error: %s", url, e)
                    break

        return b""
