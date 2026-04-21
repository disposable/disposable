"""Constants and configuration for disposable email domain detection."""

import re
import string
import random

# Regex patterns for validation and extraction
RETRY_ERRORS_RE = re.compile(r"""(The read operation timed out|urlopen error timed out)""", re.I)
DOMAIN_RE = re.compile(r"^[a-z\d-]{1,63}(\.[a-z-\.]{2,63})+$")
DOMAIN_SEARCH_RE = re.compile(r'["\'\s>]([a-z\d\.-]{1,63}\.[a-z\-]{2,63})["\'\s<]', re.I)
HTML_GENERIC_RE = re.compile(r"""<option[^>]*>@?([a-z\-\.\&#;\d+]+)\s*(\(PW\))?<\/option>""", re.I)
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}")

# Default source URLs
DISPOSABLE_WHITELIST_URL = "https://raw.githubusercontent.com/disposable/disposable/master/whitelist.txt"
DISPOSABLE_GREYLIST_URL = "https://raw.githubusercontent.com/disposable/disposable/master/greylist.txt"


def generate_random_string(length: int) -> str:
    """Generate a random string of lowercase letters."""
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for _ in range(length))  # nosec B311 - Not used for crypto/security
