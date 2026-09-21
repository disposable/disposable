"""Tests for per-source retention cache and delta guardrail."""

import json
import time

import pytest

from disposablehosts.generator import DeltaCheckError, disposableHostGenerator


def _gen(tmp_path, **options):
    return disposableHostGenerator(options=options, out_file=str(tmp_path / "domains"))


class TestSourceRetains:
    """Retention eligibility per source type."""

    @pytest.mark.parametrize("stype", ["custom", "html", "ws"])
    def test_crawled_types_retain(self, tmp_path, stype):
        assert _gen(tmp_path)._source_retains({"type": stype, "src": "x"})

    @pytest.mark.parametrize("stype", ["list", "json", "sha1", "file", "whitelist", "greylist"])
    def test_compilation_types_do_not_retain(self, tmp_path, stype):
        assert not _gen(tmp_path)._source_retains({"type": stype, "src": "x"})

    def test_retain_flag_overrides_default(self, tmp_path):
        gen = _gen(tmp_path)
        assert gen._source_retains({"type": "list", "src": "x", "retain": True})
        assert not gen._source_retains({"type": "custom", "src": "x", "retain": False})


class TestRetentionStamping:
    """_postprocess_data records seen domains for retained sources."""

    def test_stamps_domains_for_crawled_source(self, tmp_path):
        gen = _gen(tmp_path)
        source = {"type": "custom", "src": "TestSrc"}
        gen._postprocess_data(source, b"", ["alpha-test.com", "beta-test.org"])
        assert set(gen.source_cache["TestSrc"]) == {"alpha-test.com", "beta-test.org"}

    def test_no_stamp_for_compilation_source(self, tmp_path):
        gen = _gen(tmp_path)
        gen._postprocess_data({"type": "list", "src": "https://example.com/list"}, b"", ["alpha-test.com"])
        assert gen.source_cache == {}

    def test_no_stamp_on_empty_results(self, tmp_path):
        gen = _gen(tmp_path)
        res = gen._postprocess_data({"type": "custom", "src": "TestSrc"}, b"", [])
        assert res is False
        assert gen.source_cache == {}


class TestApplyRetention:
    """Cached domains merge back into results within the TTL."""

    def test_merges_fresh_cached_domain(self, tmp_path):
        gen = _gen(tmp_path)
        gen.source_cache = {"OldSrc": {"cached-domain.com": time.time()}}
        gen._apply_retention()
        assert "cached-domain.com" in gen.domains

    def test_expired_entry_dropped(self, tmp_path):
        gen = _gen(tmp_path, retention_days=1)
        gen.source_cache = {"OldSrc": {"stale-domain.com": time.time() - 3 * 86400}}
        gen._apply_retention()
        assert "stale-domain.com" not in gen.domains

    def test_disabled_when_zero_days(self, tmp_path):
        gen = _gen(tmp_path, retention_days=0)
        gen.source_cache = {"OldSrc": {"cached-domain.com": time.time()}}
        gen._apply_retention()
        assert "cached-domain.com" not in gen.domains

    def test_invalid_cached_domain_skipped(self, tmp_path):
        gen = _gen(tmp_path)
        gen.source_cache = {"OldSrc": {"not a domain": time.time()}}
        gen._apply_retention()
        assert not gen.domains

    def test_whitelist_applies_to_retained(self, tmp_path):
        gen = _gen(tmp_path)
        gen.source_cache = {"OldSrc": {"cached-domain.com": time.time()}}
        gen._apply_retention()
        gen.skip = {"cached-domain.com"}
        gen._apply_whitelist()
        assert "cached-domain.com" not in gen.domains


class TestSourceCacheFile:
    """Cache file persistence."""

    def test_write_and_load_roundtrip(self, tmp_path):
        gen = _gen(tmp_path)
        gen.source_cache = {"SrcA": {"alpha-test.com": time.time()}}
        gen._write_source_cache()
        raw = json.loads((tmp_path / "source_cache.json").read_text())
        assert "alpha-test.com" in raw["SrcA"]

        gen2 = _gen(tmp_path)
        gen2._load_source_cache()
        assert "alpha-test.com" in gen2.source_cache["SrcA"]

    def test_write_prunes_expired(self, tmp_path):
        gen = _gen(tmp_path, retention_days=1)
        gen.source_cache = {
            "SrcA": {"fresh-domain.com": time.time(), "stale-domain.com": time.time() - 3 * 86400},
        }
        gen._write_source_cache()
        raw = json.loads((tmp_path / "source_cache.json").read_text())
        assert raw == {"SrcA": {"fresh-domain.com": raw["SrcA"]["fresh-domain.com"]}}

    def test_writes_once(self, tmp_path):
        gen = _gen(tmp_path)
        gen._write_source_cache()
        gen.source_cache = {"SrcB": {"late-domain.com": time.time()}}
        gen._write_source_cache()
        raw = json.loads((tmp_path / "source_cache.json").read_text())
        assert "SrcB" not in raw

    def test_missing_cache_file_tolerated(self, tmp_path):
        gen = _gen(tmp_path)
        gen._load_source_cache()
        assert gen.source_cache == {}

    def test_corrupt_cache_file_tolerated(self, tmp_path):
        (tmp_path / "source_cache.json").write_text("{not json")
        gen = _gen(tmp_path)
        gen._load_source_cache()
        assert gen.source_cache == {}


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
