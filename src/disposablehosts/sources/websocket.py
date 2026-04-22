"""WebSocket source handling for WebSocket-based sources."""

from ..remote_data import remoteData


def fetch_websocket_source(src: str) -> bytes:
    """Fetch data from a WebSocket source.

    Args:
        src: WebSocket URL to connect to.

    Returns:
        Data received from WebSocket as bytes.
    """
    return remoteData.fetch_ws(src)
