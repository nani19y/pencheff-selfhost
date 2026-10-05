"""LRU cache + disk spill correctness."""

from __future__ import annotations

import time

from pencheff.core.orchestrator.cache import OrchestratorCache


def test_get_set_round_trip(tmp_path):
    cache = OrchestratorCache(cache_dir=tmp_path)
    key = cache.make_key(tool="nmap", target="t", args=["-sS"])
    cache.set(key, ["finding"], ttl=60)
    assert cache.get(key) == ["finding"]


def test_lru_eviction_in_memory():
    cache = OrchestratorCache(max_entries=2)
    k1 = cache.make_key(tool="a", target="t", args=[])
    k2 = cache.make_key(tool="b", target="t", args=[])
    k3 = cache.make_key(tool="c", target="t", args=[])
    cache.set(k1, 1, ttl=60)
    cache.set(k2, 2, ttl=60)
    cache.set(k3, 3, ttl=60)  # evicts k1
    assert cache.get(k1) is None
    assert cache.get(k2) == 2
    assert cache.get(k3) == 3


def test_get_resets_lru_position():
    cache = OrchestratorCache(max_entries=2)
    k1 = cache.make_key(tool="a", target="t", args=[])
    k2 = cache.make_key(tool="b", target="t", args=[])
    k3 = cache.make_key(tool="c", target="t", args=[])
    cache.set(k1, 1, ttl=60)
    cache.set(k2, 2, ttl=60)
    cache.get(k1)         # touch k1, k2 is now LRU
    cache.set(k3, 3, ttl=60)
    assert cache.get(k1) == 1
    assert cache.get(k2) is None


def test_ttl_expiry():
    cache = OrchestratorCache()
    key = cache.make_key(tool="a", target="t", args=[])
    cache.set(key, "value", ttl=0.05)
    time.sleep(0.1)
    assert cache.get(key) is None


def test_disk_spill_round_trip(tmp_path):
    c1 = OrchestratorCache(max_entries=1, cache_dir=tmp_path)
    k1 = c1.make_key(tool="a", target="t", args=[])
    k2 = c1.make_key(tool="b", target="t", args=[])
    c1.set(k1, ["alpha"], ttl=600)
    c1.set(k2, ["beta"], ttl=600)
    # k1 evicted from memory but should survive on disk; same key in a fresh
    # cache should hit the disk store.
    c2 = OrchestratorCache(max_entries=10, cache_dir=tmp_path)
    assert c2.get(k1) == ["alpha"]


def test_make_key_is_deterministic():
    a = OrchestratorCache.make_key(tool="nmap", target="t", args=["-sS", "-sV"])
    b = OrchestratorCache.make_key(tool="nmap", target="t", args=["-sS", "-sV"])
    c = OrchestratorCache.make_key(tool="nmap", target="t", args=["-sV", "-sS"])
    assert a == b
    assert a != c  # arg order matters — by design
