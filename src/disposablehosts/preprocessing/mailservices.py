"""mailservices.json preprocessing - extract whitelist- and greylist-eligible mail domains."""

import json
import logging
from typing import List, Optional, Set, Tuple

# Pricing classes whose hosts are legitimate mail providers that must never
# appear in the output.
WHITELIST_COSTS = frozenset({"free", "paid", "freemium"})

# Service categories whose hosts are legitimate special-use names.
WHITELIST_TYPES = frozenset({"reserved"})

# Service categories that are always greylist-eligible (strict tier): alias and
# forwarding services regardless of their signup verification.
GREY_TYPES = frozenset({"forwarding"})

# Signup verifications that still allow anonymous use. Priced providers that
# offer any of these are greylist-eligible (strict tier) instead of
# whitelisted; unset verification never counts as anonymous.
ANON_SIGNUP_VERIFICATIONS = frozenset({"none", "email"})

# Pricing values stored under `type` before the costs/type field split.
_LEGACY_PRICE_TYPES = frozenset({"free", "paid", "freemium"})


def _service_fields(service: dict) -> Tuple[Optional[str], Optional[str]]:
    """Return (category, pricing) for a service entry.

    Tolerates the legacy format where `type` held the pricing class:
    old `type` values free/paid/freemium are read as `costs`, category
    values (forwarding/reserved/...) stay `type`.
    """
    svc_type = service.get("type")
    costs = service.get("costs")
    if costs is None and svc_type in _LEGACY_PRICE_TYPES:
        costs, svc_type = svc_type, None
    return svc_type, costs


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
    Discontinued services are excluded from both tiers: they cannot sign
    anyone up and no longer have legitimate use to protect.
    """
    whitelist: Set[str] = set()
    grey: Set[str] = set()
    for service in raw.values():
        if not isinstance(service, dict) or service.get("discontinued"):
            continue
        hosts = {str(host).lower() for host in service.get("hosts", []) if isinstance(host, str) and host}
        if not hosts:
            continue
        svc_type, costs = _service_fields(service)
        verification = service.get("signup_verification")
        verifications = {verification} if isinstance(verification, str) else set(verification or [])
        if svc_type in GREY_TYPES or (costs in WHITELIST_COSTS and verifications & ANON_SIGNUP_VERIFICATIONS):
            grey.update(hosts)
        elif costs in WHITELIST_COSTS or svc_type in WHITELIST_TYPES:
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


def preprocess_mailservices_forwarding(data: bytes, encoding: str = "utf-8") -> Optional[dict]:
    """Extract forwarding/alias-type service hosts with provider metadata.

    Returns:
        Dict mapping each host to {"svc", "type", "verification", "remark"},
        or None if invalid/empty.
    """
    raw = _parse(data, encoding)
    if raw is None:
        return None

    result = {}
    for name, service in raw.items():
        if not isinstance(service, dict) or service.get("discontinued"):
            continue
        if service.get("type") != "forwarding":
            continue
        meta = {
            "svc": name,
            "type": "forwarding",
            "verification": service.get("signup_verification") or [],
        }
        if service.get("remark"):
            meta["remark"] = service["remark"]
        for host in service.get("hosts", []):
            if isinstance(host, str) and host:
                result[host.lower()] = meta
    if not result:
        logging.warning("No forwarding-type hosts in mailservices.json")
        return None
    return result


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
