"""CTF challenge classifier + dispatcher.

Pure pattern matching. The classifier picks a sub-solver based on the file
type (magic bytes, extension) or text shape. Replaces a black-box workflow
manager with a small decision table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from pencheff.modules.ctf.crypto.classical import auto_decode


@dataclass
class ChallengeKind:
    name: str
    rationale: str


_TEXT_HINTS: tuple[tuple[re.Pattern[str], str, str, str], ...] = (
    # (regex, name, rationale, mode) — mode is "fullmatch" or "search".
    (re.compile(r"flag\{[^}]*\}|ctf\{[^}]*\}", re.I), "flag_obvious",
     "Flag literally present", "search"),
    (re.compile(r"^[A-Za-z0-9+/=]{20,}$"), "base64",
     "Long base64-shaped string", "fullmatch"),
    (re.compile(r"^[A-Z2-7=]{20,}$"),     "base32",
     "All-caps + digits 2-7 = base32", "fullmatch"),
    (re.compile(r"^[0-9a-f]{8,}$", re.I), "hex",
     "Hex run", "fullmatch"),
    (re.compile(r"^[. -/]+$"),             "morse",
     "Only dots / dashes", "fullmatch"),
)


_FILE_HINTS: tuple[tuple[bytes, str, str], ...] = (
    (b"\x89PNG", "stego_image_png",     "PNG header — try LSB / zsteg"),
    (b"\xff\xd8\xff", "stego_image_jpeg","JPEG header — try steghide / stegseek"),
    (b"BM",      "stego_image_bmp",     "BMP header — try LSB"),
    (b"RIFF",    "stego_audio_wav",     "RIFF/WAV — try LSB / spectrogram"),
    (b"PK",      "stego_archive_zip",   "ZIP — try password recovery / nested"),
    (b"%PDF",    "forensics_pdf",       "PDF — try pdfinfo / pdfid"),
    (b"\x7fELF", "binary_elf",          "ELF — checksec + radare2"),
    (b"MZ",      "binary_pe",           "PE — pe-bear / radare2"),
    (b"\x1f\x8b","forensics_gzip",      "gzip — gunzip and recurse"),
    (b"PCAP",    "forensics_pcap",      "PCAP — wireshark / tshark"),
    (b"\xd4\xc3\xb2\xa1", "forensics_pcap","PCAP magic — tshark"),
)


def classify_text(text: str) -> ChallengeKind | None:
    needle = text.strip()
    if not needle:
        return None
    for pat, name, rationale, mode in _TEXT_HINTS:
        matched = pat.search(needle) if mode == "search" else pat.fullmatch(needle)
        if matched:
            return ChallengeKind(name=name, rationale=rationale)
    return None


def classify_file(path: str | Path) -> ChallengeKind | None:
    p = Path(path)
    if not p.is_file():
        return None
    head = p.open("rb").read(8)
    for magic, name, rationale in _FILE_HINTS:
        if head.startswith(magic):
            return ChallengeKind(name=name, rationale=rationale)
    # Fallback: extension-based.
    if p.suffix.lower() in {".txt", ".log"}:
        return ChallengeKind(name="text_unknown", rationale="text file fallback")
    return ChallengeKind(name="unknown_binary", rationale="no magic match")


def solve_text(text: str, *, depth: int = 4) -> list[tuple[str, str]]:
    """Run ``auto_decode`` and surface decoded results."""
    return auto_decode(text, depth=depth)


def candidate_tools(kind: ChallengeKind) -> Iterable[str]:
    """Suggest deterministic tools for the kind. Drives ``ctf_solve`` workflow."""
    mapping = {
        "stego_image_png":  ("zsteg", "stegsolve", "exiftool", "binwalk"),
        "stego_image_jpeg": ("stegseek", "steghide", "exiftool", "binwalk"),
        "stego_image_bmp":  ("zsteg", "exiftool"),
        "stego_audio_wav":  ("audacity", "exiftool"),
        "forensics_pcap":   ("tshark", "wireshark"),
        "forensics_pdf":    ("exiftool", "binwalk", "qpdf"),
        "forensics_gzip":   ("gunzip", "file"),
        "binary_elf":       ("file", "checksec", "radare2", "ROPgadget"),
        "binary_pe":        ("file", "radare2"),
        "text_unknown":     ("pencheff_ctf_classical",),
    }
    return mapping.get(kind.name, ("file",))
