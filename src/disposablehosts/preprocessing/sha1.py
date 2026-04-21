"""SHA1 hash preprocessing."""

import logging
from typing import Set

from ..constants import SHA1_RE


def preprocess_sha1(data: bytes, sha1_set: Set[str]) -> int:
    """Preprocess SHA1 data and add valid hashes to the set.

    Args:
        data: Raw bytes containing SHA1 hashes.
        sha1_set: Set to add valid SHA1 hashes to.

    Returns:
        Count of valid SHA1 hashes added.
    """
    count = 0
    for sha1_str in [line.decode("ascii").lower() for line in data.splitlines()]:
        if not sha1_str or not SHA1_RE.match(sha1_str):
            continue

        count += 1
        sha1_set.add(sha1_str)

    if count < 1:
        logging.warning("SHA1 source did not return any valid sha1 hash")

    return count
