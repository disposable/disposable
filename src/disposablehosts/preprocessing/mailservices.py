"""mailservices.json preprocessing - extract whitelist- and greylist-eligible mail domains."""

import json
import logging
from typing import List, Optional, Set, Tuple

# Service types whose hosts are legitimate mail providers that must never
# appear in the output.
WHITELIST_TYPES = frozenset({"free", "paid", "reserved"})

# Service types that are always greylist-eligible (strict tier): alias and
# forwarding services regardless of their signup verification.
GREY_TYPES = frozenset({"forwarding"})

# Signup verifications that still allow anonymous use. Providers with free/
# paid type that offer any of these are greylist-eligible (strict tier)
# instead of whitelisted; unset verification never counts as anonymous.
ANON_SIGNUP_VERIFICATIONS = frozenset({"none", "email"})


def _parse(data: bytes, encoding: str) -> Optional[dict]:
    try:
        raw = json.loads(data.decode(encoding))
    except Exception as e:
        logging.warning("Failed to parse mailservices.json: %s", e)
        return None
    if not isinstance(raw, dict):
        logging.warning("mailservices.json is not an object")
        return None
    return raw


def _split_hosts(raw: dict) -> Tuple[Set[str], Set[str]]:
    """Split catalog hosts into (whitelist, greylist) sets.

    A host that is greylist-eligible through any provider entry is never
    whitelisted, even if another entry lists it as whitelist-eligible.
    """
    whitelist: Set[str] = set()
    grey: Set[str] = set()
    for service in raw.values():
        if not isinstance(service, dict):
            continue
        hosts = {str(host).lower() for host in service.get("hosts", []) if isinstance(host, str) and host}
        if not hosts:
            continue
        svc_type = service.get("type")
        verification = service.get("signup_verification")
        verifications = {verification} if isinstance(verification, str) else set(verification or [])
        if svc_type in GREY_TYPES or (svc_type in ("free", "paid") and verifications & ANON_SIGNUP_VERIFICATIONS):
            grey.update(hosts)
        elif svc_type in WHITELIST_TYPES:
            whitelist.update(hosts)
    return whitelist - grey, grey


def preprocess_mailservices(data: bytes, encoding: str = "utf-8") -> Optional[List[str]]:
    """Extract domain hosts of whitelist-eligible service types.

    Args:
        data: Raw mailservices.json bytes to process.
        encoding: Character encoding to use for decoding.

    Returns:
        Sorted list of domain hostnames, or None if invalid/empty.
    """
    raw = _parse(data, encoding)
    if raw is None:
        return None

    whitelist, _ = _split_hosts(raw)
    if not whitelist:
        logging.warning("No whitelist-eligible hosts in mailservices.json")
        return None
    return sorted(whitelist)


def preprocess_mailservices_grey(data: bytes, encoding: str = "utf-8") -> Optional[List[str]]:
    """Extract domain hosts of greylist-eligible service types.

    Returns:
        Sorted list of domain hostnames, or None if invalid/empty.
    """
    raw = _parse(data, encoding)
    if raw is None:
        return None

    _, grey = _split_hosts(raw)
    if not grey:
        logging.warning("No greylist-eligible hosts in mailservices.json")
        return None
    return sorted(grey)
