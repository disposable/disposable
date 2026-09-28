"""DuckDB-backed per-source domain history with a retirement window.

Mirrors the cloud-ip-ranges history mechanism: every successfully fetched
source reconciles its current domain set against ``domain_history`` in one
transaction - new domains get ``first_seen``/``last_seen`` stamps, returning
domains are re-activated, absent domains are marked ``retired_at``, and
retirements older than the retention window are purged.

``injectable_domains`` returns the domains that retention should merge back
into the generated output: entries of sources flagged ``retain`` plus orphaned
sources that are no longer configured at all (their last pool lingers until it
expires). Upstream compilation lists are tracked for analytics but never
injected - a removal there is an intentional delisting, not pool rotation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, Optional, Set

import duckdb


class DomainHistory:
    """Per-source domain history backed by a DuckDB file."""

    def __init__(self, path: os.PathLike | str, retention_days: int = 30) -> None:
        self.path = Path(path)
        self.retention_days = retention_days
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = duckdb.connect(str(self.path))
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_history (
                source      VARCHAR NOT NULL,
                domain      VARCHAR NOT NULL,
                first_seen  TIMESTAMPTZ NOT NULL,
                last_seen   TIMESTAMPTZ NOT NULL,
                retired_at  TIMESTAMPTZ,
                PRIMARY KEY (source, domain)
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS source_stats (
                source          VARCHAR PRIMARY KEY,
                last_crawled_at TIMESTAMPTZ NOT NULL,
                last_changed_at TIMESTAMPTZ NOT NULL,
                active_count    INTEGER NOT NULL DEFAULT 0,
                retired_count   INTEGER NOT NULL DEFAULT 0,
                domains_hash    VARCHAR
            )
        """)
        self._migrate_legacy_cache()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "DomainHistory":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _migrate_legacy_cache(self) -> None:
        """Import a pre-DuckDB source_cache.json once, then set it aside."""
        legacy = self.path.parent / "source_cache.json"
        if not legacy.exists():
            return
        try:
            raw = json.loads(legacy.read_text())
        except (ValueError, OSError):
            raw = {}
        rows = [
            (str(src), str(domain), float(ts))
            for src, entries in (raw.items() if isinstance(raw, dict) else [])
            for domain, ts in (entries.items() if isinstance(entries, dict) else [])
        ]
        if rows:
            self._conn.execute("CREATE TEMP TABLE legacy_cache (source VARCHAR, domain VARCHAR, seen DOUBLE)")
            self._conn.executemany("INSERT INTO legacy_cache VALUES (?, ?, ?)", rows)
            self._conn.execute("""
                INSERT OR IGNORE INTO domain_history (source, domain, first_seen, last_seen, retired_at)
                SELECT source, domain, to_timestamp(seen), to_timestamp(seen), NULL
                FROM legacy_cache
            """)
            self._conn.execute("DROP TABLE legacy_cache")
            logging.info("Migrated %d domain(s) from source_cache.json to history DB", len(rows))
        legacy.rename(legacy.with_suffix(".json.migrated"))

    @staticmethod
    def _hash(domains: Iterable[str]) -> str:
        return hashlib.sha256(",".join(sorted(domains)).encode()).hexdigest()[:16]

    def reconcile(self, seen: Dict[str, Set[str]], now: Optional[datetime] = None) -> None:
        """Reconcile this run's per-source domain sets against the history.

        Only sources listed in ``seen`` are reconciled: a source that failed
        or was not requested keeps its previous rows, so a transient outage
        never retires a pool.

        Args:
            seen: {source_name: set of domains seen this run}.
            now: run timestamp; defaults to current UTC time.
        """
        now = now or datetime.now(tz=timezone.utc)
        cutoff = now - timedelta(days=self.retention_days)
        rows = [(src, d) for src, domains in seen.items() for d in domains]

        self._conn.execute("BEGIN")
        self._conn.execute("DROP TABLE IF EXISTS current_domains")
        self._conn.execute("CREATE TEMP TABLE current_domains (source VARCHAR NOT NULL, domain VARCHAR NOT NULL)")
        if rows:
            self._conn.executemany("INSERT INTO current_domains VALUES (?, ?)", rows)

        # 1. Insert truly new domains
        self._conn.execute(
            """
            INSERT INTO domain_history (source, domain, first_seen, last_seen, retired_at)
            SELECT c.source, c.domain, $1, $1, NULL
            FROM current_domains c
            LEFT JOIN domain_history h ON h.source = c.source AND h.domain = c.domain
            WHERE h.domain IS NULL
            """,
            [now],
        )

        # 2. Re-activate retired domains that are back
        self._conn.execute(
            """
            UPDATE domain_history SET last_seen = $1, retired_at = NULL
            WHERE retired_at IS NOT NULL
            AND (source, domain) IN (SELECT source, domain FROM current_domains)
            """,
            [now],
        )

        # 3. Update last_seen for continuing active domains
        self._conn.execute(
            """
            UPDATE domain_history SET last_seen = $1
            WHERE retired_at IS NULL
            AND (source, domain) IN (SELECT source, domain FROM current_domains)
            """,
            [now],
        )

        # 4. Retire domains missing from sources that ran this time
        self._conn.execute(
            """
            UPDATE domain_history SET retired_at = $1
            WHERE retired_at IS NULL
            AND source IN (SELECT DISTINCT source FROM current_domains)
            AND (source, domain) NOT IN (SELECT source, domain FROM current_domains)
            """,
            [now],
        )

        # 5. Purge retirements beyond the retention window
        self._conn.execute("DELETE FROM domain_history WHERE retired_at IS NOT NULL AND retired_at < $1", [cutoff])

        # 6. Per-source stats (sources that ran this time)
        for src, domains in seen.items():
            new_hash = self._hash(domains)
            prev = self._conn.execute("SELECT last_changed_at, domains_hash FROM source_stats WHERE source = ?", [src]).fetchone()
            changed_at = prev[0] if prev and prev[1] == new_hash else now
            retired_count_row = self._conn.execute("SELECT count(*) FROM domain_history WHERE source = ? AND retired_at IS NOT NULL", [src]).fetchone()
            retired_count = retired_count_row[0] if retired_count_row else 0
            self._conn.execute(
                """
                INSERT INTO source_stats (source, last_crawled_at, last_changed_at, active_count, retired_count, domains_hash)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (source) DO UPDATE SET
                    last_crawled_at = $2, last_changed_at = $3,
                    active_count = $4, retired_count = $5, domains_hash = $6
                """,
                [src, now, changed_at, len(domains), retired_count, new_hash],
            )

        self._conn.execute("COMMIT")

    def injectable_domains(self, retain: Set[str], configured: Set[str], now: Optional[datetime] = None) -> Set[str]:
        """Domains to merge back into the output under retention rules.

        A domain qualifies when its source is flagged ``retain`` or is no
        longer configured (orphaned source whose last pool lingers), and it
        was either retired within the window or is still active but its source
        did not produce it this run (last_seen within the window).

        Args:
            retain: source names with the ``retain`` flag.
            configured: all configured source names.
            now: reference timestamp; defaults to current UTC time.

        Returns:
            Set of domains to merge into the generated output.
        """
        now = now or datetime.now(tz=timezone.utc)
        cutoff = now - timedelta(days=self.retention_days)
        rows = self._conn.execute(
            """
            SELECT DISTINCT domain FROM domain_history
            WHERE (list_contains($1, source) OR NOT list_contains($2, source))
            AND ((retired_at IS NOT NULL AND retired_at >= $3)
                 OR (retired_at IS NULL AND last_seen >= $3))
            """,
            [sorted(retain), sorted(configured), cutoff],
        ).fetchall()
        return {row[0] for row in rows}
