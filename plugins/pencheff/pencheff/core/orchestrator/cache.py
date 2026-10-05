"""LRU cache with optional disk spill, keyed on tool invocations.

Backed by an in-memory ``OrderedDict`` for hot reads + an on-disk
``cache_dir`` of pickle files keyed by SHA-256(invocation). Items expire
once ``ttl`` seconds elapse; expired entries are evicted lazily on access.
"""

from __future__ import annotations

import hashlib
import os
import pickle
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class CacheEntry:
    key: str
    value: Any
    inserted_at: float
    ttl: float

    @property
    def expired(self) -> bool:
        return self.ttl > 0 and (time.time() - self.inserted_at) > self.ttl


class OrchestratorCache:
    def __init__(
        self,
        *,
        max_entries: int = 512,
        cache_dir: Path | str | None = None,
    ) -> None:
        self._max = max_entries
        self._mem: "OrderedDict[str, CacheEntry]" = OrderedDict()
        self._lock = threading.Lock()
        self._dir: Path | None = Path(cache_dir) if cache_dir else None
        if self._dir:
            self._dir.mkdir(parents=True, exist_ok=True)

    # ─── key construction ───────────────────────────────────────────────
    @staticmethod
    def make_key(*, tool: str, target: str, args: list[str], scope_hash: str = "") -> str:
        norm_args = " ".join(args)
        h = hashlib.sha256(
            f"{tool}|{target}|{scope_hash}|{norm_args}".encode("utf-8")
        ).hexdigest()
        return h

    # ─── public API ─────────────────────────────────────────────────────
    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._mem.get(key)
            if entry is not None:
                if entry.expired:
                    self._mem.pop(key, None)
                    self._unlink_disk(key)
                    return None
                self._mem.move_to_end(key)
                return entry.value
            entry = self._load_disk(key)
            if entry is None:
                return None
            if entry.expired:
                self._unlink_disk(key)
                return None
            self._mem[key] = entry
            self._mem.move_to_end(key)
            self._evict()
            return entry.value

    def set(self, key: str, value: Any, *, ttl: float = 3600) -> None:
        entry = CacheEntry(key=key, value=value, inserted_at=time.time(), ttl=ttl)
        with self._lock:
            self._mem[key] = entry
            self._mem.move_to_end(key)
            self._evict()
            self._dump_disk(entry)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"entries": len(self._mem), "max": self._max}

    def clear(self) -> None:
        with self._lock:
            self._mem.clear()
            if self._dir and self._dir.is_dir():
                for p in self._dir.glob("*.pkl"):
                    try:
                        p.unlink()
                    except OSError:
                        pass

    # ─── helpers ────────────────────────────────────────────────────────
    def _evict(self) -> None:
        # Memory-LRU eviction only; the disk copy stays so a later get()
        # can rehydrate. Disk entries are reaped via TTL expiry only.
        while len(self._mem) > self._max:
            self._mem.popitem(last=False)

    def _disk_path(self, key: str) -> Path | None:
        if not self._dir:
            return None
        return self._dir / f"{key}.pkl"

    def _dump_disk(self, entry: CacheEntry) -> None:
        path = self._disk_path(entry.key)
        if not path:
            return
        tmp = path.with_suffix(".pkl.tmp")
        try:
            with tmp.open("wb") as fh:
                pickle.dump(entry, fh)
            os.replace(tmp, path)
        except OSError:
            # Cache is best-effort; never blow up the engagement on disk error.
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def _load_disk(self, key: str) -> CacheEntry | None:
        path = self._disk_path(key)
        if not path or not path.is_file():
            return None
        try:
            with path.open("rb") as fh:
                return pickle.load(fh)
        except (OSError, pickle.UnpicklingError, EOFError):
            return None

    def _unlink_disk(self, key: str) -> None:
        path = self._disk_path(key)
        if path and path.is_file():
            try:
                path.unlink()
            except OSError:
                pass
