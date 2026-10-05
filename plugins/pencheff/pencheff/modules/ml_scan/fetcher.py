# pencheff/modules/ml_scan/fetcher.py
"""Bounded, best-effort retrieval of model artifacts into an MlManifest.
NEVER deserializes — only reads bytes and classifies by magic. Network/file
errors are non-fatal (recorded in mf.fetch_errors)."""
from __future__ import annotations

import logging
import os

import httpx

from .format_detect import detect_format
from .manifest import MlArtifact, MlManifest

log = logging.getLogger("pencheff.modules.ml_scan.fetcher")

_DEFAULT_MAX = 524_288_000          # 500 MB
_HF_API = "https://huggingface.co/api/models/{repo}"
_HF_FILE = "https://huggingface.co/{repo}/resolve/{rev}/{path}"
# HF filenames worth fetching for static inspection (skip giant safe shards if huge)
_INTERESTING = (".pkl", ".pickle", ".bin", ".pt", ".pth", ".ckpt", ".h5",
                ".keras", ".joblib", ".safetensors", ".gguf", ".onnx", ".npy")


def _bounded(data: bytes, max_bytes: int) -> bytes:
    return data[:max_bytes] if max_bytes and len(data) > max_bytes else data


async def build_manifest(cfg: dict) -> MlManifest:
    st = cfg.get("source_type")
    max_bytes = int(cfg.get("max_bytes") or _DEFAULT_MAX)
    if st == "local_path":
        return _from_local(cfg, max_bytes)
    if st == "file_url":
        return await _from_url(cfg, max_bytes)
    if st == "huggingface":
        return await _from_hf(cfg, max_bytes)
    mf = MlManifest(source_type=str(st), origin="")
    mf.fetch_errors.append(f"unsupported source_type {st!r}")
    return mf


def _from_local(cfg: dict, max_bytes: int) -> MlManifest:
    path = cfg.get("local_path") or ""
    mf = MlManifest(source_type="local_path", origin=path)
    try:
        with open(path, "rb") as fh:
            data = _bounded(fh.read(max_bytes + 1), max_bytes)
        name = os.path.basename(path) or "artifact"
        mf.artifacts.append(MlArtifact(name=name, data=data,
                                       fmt=detect_format(data, name), size=len(data)))
    except Exception as e:
        mf.fetch_errors.append(f"local read failed: {e}")
    return mf


async def _from_url(cfg: dict, max_bytes: int) -> MlManifest:
    url = cfg.get("url") or ""
    mf = MlManifest(source_type="file_url", origin=url)
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
            data = await _get_bounded(client, url, max_bytes, cfg)
        name = url.rsplit("/", 1)[-1].split("?")[0] or "artifact"
        mf.artifacts.append(MlArtifact(name=name, data=data,
                                       fmt=detect_format(data, name), size=len(data)))
    except Exception as e:
        mf.fetch_errors.append(f"url fetch failed: {e}")
    return mf


async def _from_hf(cfg: dict, max_bytes: int) -> MlManifest:
    repo = cfg.get("hf_repo") or ""
    rev = cfg.get("hf_revision") or "main"
    mf = MlManifest(source_type="huggingface", origin=repo, provider="huggingface", hf_repo=repo)
    headers = {}
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
            meta = await client.get(_HF_API.format(repo=repo), headers=headers)
            meta.raise_for_status()
            siblings = [s.get("rfilename", "") for s in (meta.json().get("siblings") or [])]
            wanted = [f for f in siblings if f.lower().endswith(_INTERESTING)]
            mf.metadata["card_present"] = any(s.lower() == "readme.md" for s in siblings)
            for path in wanted[:20]:   # bound artifact count
                url = _HF_FILE.format(repo=repo, rev=rev, path=path)
                try:
                    data = await _get_bounded(client, url, max_bytes, cfg)
                    mf.artifacts.append(MlArtifact(name=path, data=data,
                                                   fmt=detect_format(data, path), size=len(data)))
                except Exception as e:
                    mf.fetch_errors.append(f"hf file {path} failed: {e}")
    except Exception as e:
        mf.fetch_errors.append(f"hf resolve failed: {e}")
    return mf


async def _get_bounded(client: httpx.AsyncClient, url: str, max_bytes: int, cfg: dict) -> bytes:
    """Stream up to max_bytes+1 then truncate, so we never buffer an unbounded body."""
    chunks: list[bytes] = []
    total = 0
    async with client.stream("GET", url) as resp:
        resp.raise_for_status()
        async for chunk in resp.aiter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                break
    return _bounded(b"".join(chunks), max_bytes)
