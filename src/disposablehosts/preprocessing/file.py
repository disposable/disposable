"""Plain text file preprocessing."""

from typing import List


def preprocess_file(data: bytes, encoding: str = "utf-8") -> List[str]:
    """Preprocess plain text file data.

    Args:
        data: Raw bytes to process.
        encoding: Character encoding to use for decoding.

    Returns:
        List of non-empty, non-comment lines.
    """
    lines = []
    for line in data.splitlines():
        line = line.decode(encoding).strip()
        if line.startswith("#") or line == "":
            continue
        lines.append(line)
    return lines
