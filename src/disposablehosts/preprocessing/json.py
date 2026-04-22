"""JSON data preprocessing."""

import json
import logging
import re
from typing import Any, List, Optional


def preprocess_json(data: bytes, encoding: str = "utf-8") -> Optional[List[str]]:
    """Preprocess JSON data and extract domain strings.

    Args:
        data: Raw JSON bytes to process.
        encoding: Character encoding to use for decoding.

    Returns:
        List of domain strings, or None if invalid/empty.
    """
    raw: Any = {}
    try:
        raw = json.loads(data.decode(encoding))
    except Exception as e:
        if "Unexpected UTF-8 BOM" in str(e):
            raw = json.loads(data.decode("utf-8-sig"))

    if not raw:
        logging.warning("No data in json")
        return None

    if "domains" in raw:
        raw = raw["domains"]

    if "email" in raw:
        s = re.search(r"^.+?@?([a-z0-9\.-]{1,128})$", raw["email"])
        if s:
            raw = [s[1]]

    if not isinstance(raw, list):
        logging.warning("This URL does not contain a JSON array")
        return None

    return list(filter(lambda line: line and isinstance(line, str), raw))
