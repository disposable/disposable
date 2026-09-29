"""mailservices.json preprocessing - extract whitelist-eligible mail domains."""

import json
import logging
from typing import List, Optional

# Service types whose hosts are legitimate mail providers that must never
# appear in the output. "forwarding" is excluded on purpose: alias services
# are handled by the greylist (strict tier), not the whitelist.
WHITELIST_TYPES = frozenset({"free", "paid", "reserved"})


def preprocess_mailservices(data: bytes, encoding: str = "utf-8") -> Optional[List[str]]:
    """Extract domain hosts of whitelist-eligible service types.

    Args:
        data: Raw mailservices.json bytes to process.
        encoding: Character encoding to use for decoding.

    Returns:
        Sorted list of domain hostnames, or None if invalid/empty.
    """
    try:
        raw = json.loads(data.decode(encoding))
    except Exception as e:
        logging.warning("Failed to parse mailservices.json: %s", e)
        return None

    if not isinstance(raw, dict):
        logging.warning("mailservices.json is not an object")
        return None

    hosts = {
        str(host).lower()
        for service in raw.values()
        if isinstance(service, dict) and service.get("type") in WHITELIST_TYPES
        for host in service.get("hosts", [])
        if isinstance(host, str) and host
    }
    if not hosts:
        logging.warning("No whitelist-eligible hosts in mailservices.json")
        return None

    return sorted(hosts)
