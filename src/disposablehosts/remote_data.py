"""Remote data fetching utilities."""

import logging
import time
from typing import Dict, Optional

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
        except FileNotFoundError as e:
            if ignore_errors:
                return b""
            raise e
        except IOError as e:
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
        except (IOError, Exception) as e:
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
        return (res and res.read()) or b""
