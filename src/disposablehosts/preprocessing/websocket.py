"""WebSocket data preprocessing."""

from typing import List


def preprocess_websocket(data: bytes) -> List[str]:
    """Preprocess WebSocket data and extract domains.

    Args:
        data: Raw WebSocket response bytes.

    Returns:
        List of domain strings.
    """
    for line in data.splitlines():
        line_str = line.decode("utf-8")
        if line_str.startswith("D"):
            return line_str[1:].split(",")
    return []
