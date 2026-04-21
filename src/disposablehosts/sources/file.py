"""File source handling for local file reading."""

from ..remote_data import remoteData


def fetch_file_source(src: str, ignore_not_exists: bool = False) -> bytes:
    """Fetch data from a local file.

    Args:
        src: Path to the file to read.
        ignore_not_exists: Whether to ignore errors if file doesn't exist.

    Returns:
        File contents as bytes.
    """
    return remoteData.fetch_file(src, ignore_not_exists)
