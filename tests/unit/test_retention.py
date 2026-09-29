"""Tests for DuckDB-backed domain history, retention merge and delta guardrail."""

import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from disposablehosts.generator import DeltaCheckError, disposableHostGenerator
from disposablehosts.history import DomainHistory


def _gen(tmp_path, **options):
    return disposableHostGenerator(options=options, out_file=str(tmp_path / "domains"))


def _history(tmp_path, days=30):
    return DomainHistory(tmp_path / "history.duckdb", days)


class TestSourceRetains:
    """Retention is opt-in via the per-source ``retain`` flag."""

    @pytest.mark.parametrize("stype", ["custom", "html", "ws", "json", "list"])
    def test_retain_flag_enables_any_type(self, tmp_path, stype):
        assert _gen(tmp_path)._source_retains({"type": stype, "src": "x", "retain": True})

    @pytest.mark.parametrize("stype", ["custom", "html", "ws", "json", "list", "sha1", "file"])
    def test_unflagged_sources_do_not_retain(self, tmp_path, stype):
        assert not _gen(tmp_path)._source_retains({"type": stype, "src": "x"})

    def test_retain_false_explicit(self, tmp_path):
        assert not _gen(tmp_path)._source_retains({"type": "custom", "src": "x", "retain": False})

    def test_configured_sources_flagged_correctly(self):
        """Crawled sources are flagged, upstream compilations are not."""
        flagged = {s["src"] for s in disposableHostGenerator().sources if s.get("retain")}
        unflagged = {s["src"] for s in disposableHostGenerator().sources if not s.get("retain")}
        assert flagged  # sanity: at least some sources retain
        compilation_types = ("list", "sha1", "file", "whitelist", "whitelist_file", "whitelist_mailservices", "greylist", "greylist_file")
        assert all(s.get("type") in compilation_types for s in disposableHostGenerator().sources if s["src"] in unflagged)


class TestDomainSeenBuffering:
    """_postprocess_data buffers seen domains per source for reconciliation."""

    def test_stamps_domains_for_source(self, tmp_path):
        gen = _gen(tmp_path)
        source = {"type": "custom", "src": "TestSrc", "retain": True}
        gen._postprocess_data(source, b"", ["alpha-test.com", "beta-test.org"])
        assert gen.domain_seen["TestSrc"] == {"alpha-test.com", "beta-test.org"}

    def test_compilation_sources_are_tracked_too(self, tmp_path):
        """All sources feed history; injection filtering happens at merge time."""
        gen = _gen(tmp_path)
        gen._postprocess_data({"type": "list", "src": "https://example.com/list"}, b"", ["alpha-test.com"])
        assert gen.domain_seen["https://example.com/list"] == {"alpha-test.com"}

    def test_no_stamp_on_empty_results(self, tmp_path):
        gen = _gen(tmp_path)
        res = gen._postprocess_data({"type": "custom", "src": "TestSrc", "retain": True}, b"", [])
        assert res is False
        assert gen.domain_seen == {}


class TestDomainHistory:
    """DomainHistory reconcile/retire/purge semantics."""

    def test_reconcile_marks_first_and_last_seen(self, tmp_path):
        with _history(tmp_path) as h:
            h.reconcile({"Src": {"a.com", "b.com"}})
            rows = h._conn.execute("SELECT domain, retired_at FROM domain_history ORDER BY domain").fetchall()
        assert rows == [("a.com", None), ("b.com", None)]

    def test_absent_domain_retired(self, tmp_path):
        with _history(tmp_path) as h:
            h.reconcile({"Src": {"a.com", "b.com"}})
            h.reconcile({"Src": {"a.com"}})
            retired = h._conn.execute("SELECT domain FROM domain_history WHERE retired_at IS NOT NULL").fetchall()
            stats = h._conn.execute("SELECT active_count, retired_count FROM source_stats WHERE source = 'Src'").fetchone()
        assert retired == [("b.com",)]
        assert stats == (1, 1)

    def test_returned_domain_reactivated(self, tmp_path):
        with _history(tmp_path) as h:
            h.reconcile({"Src": {"a.com"}})
            h.reconcile({"Src": set()})
            h.reconcile({"Src": {"a.com"}})
            row = h._conn.execute("SELECT retired_at FROM domain_history WHERE domain = 'a.com'").fetchone()
        assert row == (None,)

    def test_expired_retirements_purged(self, tmp_path):
        with _history(tmp_path) as h:
            h.reconcile({"Src": {"a.com"}})
            h._conn.execute(
                "UPDATE domain_history SET retired_at = $1",
                [datetime.now(tz=timezone.utc) - timedelta(days=31)],
            )
            h.reconcile({"Src": {"b.com"}})
            count = h._conn.execute("SELECT count(*) FROM domain_history WHERE domain = 'a.com'").fetchone()[0]
        assert count == 0

    def test_failed_source_keeps_rows_active(self, tmp_path):
        """A source absent from reconcile input never retires its pool."""
        with _history(tmp_path) as h:
            h.reconcile({"Src": {"a.com"}})
            h.reconcile({})  # Src did not run
            row = h._conn.execute("SELECT retired_at FROM domain_history WHERE domain = 'a.com'").fetchone()
        assert row == (None,)

    def test_source_stats_last_changed(self, tmp_path):
        with _history(tmp_path) as h:
            h.reconcile({"Src": {"a.com"}})
            first = h._conn.execute("SELECT last_changed_at FROM source_stats WHERE source = 'Src'").fetchone()[0]
            h.reconcile({"Src": {"a.com"}})  # identical set -> unchanged
            same = h._conn.execute("SELECT last_changed_at FROM source_stats WHERE source = 'Src'").fetchone()[0]
            h.reconcile({"Src": {"a.com", "b.com"}})  # changed set -> bumped
            bumped = h._conn.execute("SELECT last_changed_at FROM source_stats WHERE source = 'Src'").fetchone()[0]
        assert same == first and bumped > first


class TestLegacyCacheMigration:
    """One-time import of a pre-DuckDB source_cache.json."""

    def test_json_cache_imported(self, tmp_path):
        (tmp_path / "source_cache.json").write_text(json.dumps({"OldSrc": {"alpha-test.com": time.time()}}))
        with _history(tmp_path) as h:
            row = h._conn.execute("SELECT domain, retired_at FROM domain_history").fetchall()
        assert row == [("alpha-test.com", None)]
        assert not (tmp_path / "source_cache.json").exists()
        assert (tmp_path / "source_cache.json.migrated").exists()

    def test_missing_or_corrupt_cache_tolerated(self, tmp_path):
        (tmp_path / "source_cache.json").write_text("{not json")
        with _history(tmp_path) as h:
            count = h._conn.execute("SELECT count(*) FROM domain_history").fetchone()[0]
        assert count == 0
        assert (tmp_path / "source_cache.json.migrated").exists()

    def test_no_legacy_file_no_migration(self, tmp_path):
        with _history(tmp_path):
            pass
        assert not (tmp_path / "source_cache.json.migrated").exists()


class TestApplyRetention:
    """Retained domains merge back into results within the TTL."""

    def test_merges_retired_domain_of_retain_source(self, tmp_path):
        with _history(tmp_path) as h:
            h.reconcile({"TestSrc": {"cached-domain.com"}})
        gen = _gen(tmp_path)
        gen.sources = [{"type": "custom", "src": "TestSrc", "retain": True}]
        gen.domain_seen = {"TestSrc": {"other-domain.com"}}  # ran; cached-domain.com dropped
        gen._apply_retention()
        assert "cached-domain.com" in gen.domains

    def test_merges_domain_of_failed_retain_source(self, tmp_path):
        with _history(tmp_path) as h:
            h.reconcile({"TestSrc": {"cached-domain.com"}})
        gen = _gen(tmp_path)
        gen.sources = [{"type": "custom", "src": "TestSrc", "retain": True}]
        gen.domain_seen = {}  # source failed this run
        gen._apply_retention()
        assert "cached-domain.com" in gen.domains

    def test_merges_orphaned_source_pool(self, tmp_path):
        """Sources dropped from config keep contributing until expiry."""
        with _history(tmp_path) as h:
            h.reconcile({"GoneSrc": {"cached-domain.com"}})
        gen = _gen(tmp_path)
        gen.sources = [{"type": "custom", "src": "TestSrc", "retain": True}]
        gen.domain_seen = {"TestSrc": {"a.com"}}
        gen._apply_retention()
        assert "cached-domain.com" in gen.domains

    def test_no_inject_for_configured_non_retain_source(self, tmp_path):
        """Upstream compilations are tracked but their removals stay removed."""
        with _history(tmp_path) as h:
            h.reconcile({"ListSrc": {"cached-domain.com"}})
        gen = _gen(tmp_path)
        gen.sources = [{"type": "list", "src": "ListSrc"}]
        gen.domain_seen = {"ListSrc": {"other-domain.com"}}  # ran; domain delisted
        gen._apply_retention()
        assert "cached-domain.com" not in gen.domains

    def test_expired_entry_dropped(self, tmp_path):
        with _history(tmp_path, days=1) as h:
            h.reconcile({"TestSrc": {"stale-domain.com"}})
            h._conn.execute(
                "UPDATE domain_history SET retired_at = $1, last_seen = $1",
                [datetime.now(tz=timezone.utc) - timedelta(days=3)],
            )
        gen = _gen(tmp_path, retention_days=1)
        gen.sources = [{"type": "custom", "src": "TestSrc", "retain": True}]
        gen._apply_retention()
        assert "stale-domain.com" not in gen.domains

    def test_disabled_when_zero_days(self, tmp_path):
        gen = _gen(tmp_path, retention_days=0)
        gen.domain_seen = {"TestSrc": {"cached-domain.com"}}
        gen._apply_retention()
        assert not gen.domains
        assert not (tmp_path / "history.duckdb").exists()

    def test_invalid_cached_domain_skipped(self, tmp_path):
        with _history(tmp_path) as h:
            h.reconcile({"TestSrc": {"not a domain"}})
        gen = _gen(tmp_path)
        gen.sources = [{"type": "custom", "src": "TestSrc", "retain": True}]
        gen._apply_retention()
        assert not gen.domains

    def test_whitelist_applies_to_retained(self, tmp_path):
        with _history(tmp_path) as h:
            h.reconcile({"TestSrc": {"cached-domain.com"}})
        gen = _gen(tmp_path)
        gen.sources = [{"type": "custom", "src": "TestSrc", "retain": True}]
        gen._apply_retention()
        gen.skip = {"cached-domain.com"}
        gen._apply_whitelist()
        assert not gen.domains

    def test_history_written_next_to_outfile(self, tmp_path):
        gen = _gen(tmp_path)
        gen.sources = [{"type": "custom", "src": "TestSrc", "retain": True}]
        gen.domain_seen = {"TestSrc": {"alpha-test.com"}}
        gen._apply_retention()
        assert (tmp_path / "history.duckdb").exists()
        with _history(tmp_path) as h:
            row = h._conn.execute("SELECT domain FROM domain_history WHERE source = 'TestSrc'").fetchall()
        assert row == [("alpha-test.com",)]


class TestDeltaGuard:
    """_enforce_max_delta aborts on mass removal."""

    def test_raises_on_mass_removal(self, tmp_path):
        gen = _gen(tmp_path)
        gen.old_domains = {f"d{i}.example.com" for i in range(100)}
        gen.domains = set(list(gen.old_domains)[:30])
        with pytest.raises(DeltaCheckError):
            gen._enforce_max_delta()

    def test_small_removal_passes(self, tmp_path):
        gen = _gen(tmp_path)
        gen.old_domains = {f"d{i}.example.com" for i in range(100)}
        gen.domains = set(list(gen.old_domains)[:90])  # 10% removed
        gen._enforce_max_delta()

    def test_small_list_exemption(self, tmp_path):
        gen = _gen(tmp_path)
        gen.old_domains = {f"d{i}.example.com" for i in range(30)}
        gen.domains = set()
        gen._enforce_max_delta()  # < 50 removed absolute

    def test_disabled_when_zero(self, tmp_path):
        gen = _gen(tmp_path, max_delta_ratio=0)
        gen.old_domains = {f"d{i}.example.com" for i in range(100)}
        gen.domains = set()
        gen._enforce_max_delta()

    def test_skipped_for_src_filter(self, tmp_path):
        gen = _gen(tmp_path, src_filter="TempMailOrg")
        gen.old_domains = {f"d{i}.example.com" for i in range(100)}
        gen.domains = set()
        gen._enforce_max_delta()

    def test_reads_old_domains_from_file(self, tmp_path):
        (tmp_path / "domains.txt").write_text("\n".join(f"d{i}.example.com" for i in range(100)))
        gen = _gen(tmp_path)
        gen.domains = set()
        with pytest.raises(DeltaCheckError):
            gen._enforce_max_delta()
