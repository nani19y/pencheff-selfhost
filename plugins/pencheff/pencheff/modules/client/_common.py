"""Shared helpers for client-side artifact analysis: safe unzip, file walking,
and a secrets sweep that reuses the mobile SECRET_PATTERNS."""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.modules.mobile.secrets import SECRET_PATTERNS

# Bounds to keep adversarial archives from exhausting CPU/RAM/disk.
MAX_FILES = 5000
MAX_BYTES_PER_FILE = 5_000_000  # 5 MB
MAX_TOTAL_UNCOMPRESSED = 500_000_000  # 500 MB — zip-bomb guard
TEXT_EXTS = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".json", ".html",
             ".htm", ".css", ".txt", ".md", ".yml", ".yaml", ".xml", ".env",
             ".config", ".properties", ".plist"}


def safe_unzip(zip_bytes: bytes, dest: Path) -> str | None:
    """Extract a ZIP from raw bytes into ``dest``, guarding against zip-slip
    (path traversal) and zip bombs. Returns the dest path or None on failure."""
    import io

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        return None
    total = 0
    dest = dest.resolve()
    for info in zf.infolist()[:MAX_FILES]:
        # zip-slip guard: the resolved target must stay within dest.
        target = (dest / info.filename).resolve()
        if not str(target).startswith(str(dest)):
            continue
        if info.is_dir():
            continue
        total += info.file_size
        if total > MAX_TOTAL_UNCOMPRESSED:
            break
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with zf.open(info) as src, open(target, "wb") as out:
                out.write(src.read(MAX_BYTES_PER_FILE + 1))
        except (OSError, zipfile.BadZipFile):
            continue
    return str(dest)


def crx_to_zip_bytes(raw: bytes) -> bytes | None:
    """Strip a Chrome CRX2/CRX3 header, returning the embedded ZIP bytes.
    Returns the input unchanged if it's already a plain ZIP (PK), or None if
    it's neither."""
    if raw[:2] == b"PK":
        return raw  # plain zip (XPI / unsigned)
    if raw[:4] != b"Cr24":
        return None
    version = struct.unpack("<I", raw[4:8])[0]
    if version == 3:
        header_len = struct.unpack("<I", raw[8:12])[0]
        return raw[12 + header_len:]
    if version == 2:
        pubkey_len = struct.unpack("<I", raw[8:12])[0]
        sig_len = struct.unpack("<I", raw[12:16])[0]
        return raw[16 + pubkey_len + sig_len:]
    return None


def iter_text_files(root: Path):
    """Yield (path, text) for text-like files under root, bounded."""
    count = 0
    for p in sorted(root.rglob("*")):
        if count >= MAX_FILES:
            break
        if not p.is_file() or p.suffix.lower() not in TEXT_EXTS:
            continue
        try:
            if p.stat().st_size > MAX_BYTES_PER_FILE:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        count += 1
        yield p, text


def secrets_sweep(root: Path, category: str, source_label: str,
                  max_hits: int = 25) -> list[Finding]:
    """Regex secrets sweep over text files under root, reusing SECRET_PATTERNS."""
    findings: list[Finding] = []
    hits = 0
    for p, text in iter_text_files(root):
        for name, pattern, _owasp in SECRET_PATTERNS:
            if hits >= max_hits:
                return findings
            m = pattern.search(text)
            if not m:
                continue
            hits += 1
            snippet = m.group(0)
            if len(snippet) > 60:
                snippet = snippet[:57] + "..."
            findings.append(Finding(
                title=f"Hardcoded secret — {name}",
                severity=Severity.HIGH,
                category=category,
                owasp_category="A05",
                description=(
                    f"A {name} appears hardcoded in the {source_label} bundle "
                    f"({p.name}). Client-side artifacts are fully readable by anyone "
                    f"who downloads them, so any embedded credential is effectively public."
                ),
                remediation="Remove the secret from the shipped bundle. Move it server-side or behind an authenticated API; rotate the exposed credential.",
                endpoint=str(p),
                cwe_id="CWE-798",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                evidence=[Evidence(request_method="STATIC", request_url=str(p),
                                   description=f"match: {snippet}")],
            ))
    return findings
