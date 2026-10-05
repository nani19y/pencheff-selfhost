# pencheff/modules/ml_scan/pickle_scan.py
"""Static pickle-opcode danger scanner. Uses pickletools.genops ONLY (a
disassembler) — NEVER unpickles. Mirrors picklescan/ModelScan/fickling logic,
hardened against the JFrog picklescan bypass CVEs (2025-10155/56/57):
  * route by content not extension (handled in format_detect)
  * scan EVERY embedded pickle in a zip even if the CRC is bad (don't fail-stop)
  * treat sub-module / sub-package imports of a dangerous module as dangerous
  * keep scanning past the first STOP opcode (concatenated pickles)
"""
from __future__ import annotations

import io
import pickletools
import zipfile
import zlib

# module -> dangerous names ("*" = the whole module is dangerous)
_DANGEROUS: dict[str, set[str]] = {
    "os": {"*"}, "posix": {"*"}, "nt": {"*"},
    "subprocess": {"*"}, "sys": {"*"}, "socket": {"*"},
    "shutil": {"*"}, "pty": {"*"}, "runpy": {"*"}, "webbrowser": {"*"},
    "ctypes": {"*"}, "multiprocessing": {"*"}, "asyncio": {"*"},
    "importlib": {"*"}, "imp": {"*"}, "code": {"*"}, "codeop": {"*"},
    "pickle": {"*"}, "_pickle": {"*"},
    "builtins": {"eval", "exec", "compile", "open", "__import__", "getattr",
                 "setattr", "breakpoint", "input", "globals", "vars"},
    "__builtin__": {"eval", "exec", "compile", "open", "__import__", "getattr",
                    "setattr", "breakpoint", "input", "globals", "vars"},
    "operator": {"attrgetter", "methodcaller", "itemgetter"},
    "functools": {"partial"},
}

_STRING_OPCODES = {  # opcodes that push a string (feed STACK_GLOBAL)
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
}
_REDUCE_OPCODES = {"REDUCE", "OBJ", "INST", "NEWOBJ", "NEWOBJ_EX", "BUILD"}

_NONSTR = object()  # sentinel for a stack value we don't track as a string


def _is_dangerous(module: str, name: str) -> bool:
    """True if `module` (or any dangerous parent package of it) marks `name`
    (or '*') dangerous. Prefix match implements CVE-2025-10157 hardening."""
    candidates = set()
    parts = module.split(".")
    for i in range(1, len(parts) + 1):
        candidates.add(".".join(parts[:i]))
    for cand in candidates:
        names = _DANGEROUS.get(cand)
        if names and ("*" in names or name in names):
            return True
    return False


def scan_pickle_bytes(data: bytes) -> list[dict]:
    """Disassemble `data` and return a hit dict per dangerous global reference.
    Robust: never raises on malformed input (returns what it found so far).
    Resumable across concatenated pickles (keeps scanning past STOP)."""
    hits: list[dict] = []
    # Modeled symbolic value-stack: recover STACK_GLOBAL's real top-two operands
    # regardless of memo round-trips, decoy strings, or DUP juggling.
    stack: list = []
    memo: dict[int, object] = {}
    saw_reduce = False
    offset = 0
    while offset < len(data):
        last = offset
        stopped = False
        try:
            for opcode, arg, pos in pickletools.genops(data[offset:]):
                last = offset + pos
                nm = opcode.name
                if nm in _REDUCE_OPCODES:
                    saw_reduce = True
                module = name = None
                if nm in _STRING_OPCODES and isinstance(arg, str):
                    stack.append(arg)
                elif nm == "MEMOIZE":
                    if stack:
                        memo[len(memo)] = stack[-1]
                elif nm in ("PUT", "BINPUT", "LONG_BINPUT"):
                    if stack and arg is not None:
                        memo[int(arg)] = stack[-1]
                elif nm in ("GET", "BINGET", "LONG_BINGET"):
                    stack.append(memo.get(int(arg), _NONSTR) if arg is not None
                                 else _NONSTR)
                elif nm == "DUP":
                    if stack:
                        stack.append(stack[-1])
                elif nm == "POP":
                    if stack:
                        stack.pop()
                elif nm in ("GLOBAL", "INST"):
                    # genops gives "module name" (space-joined) for GLOBAL/INST
                    if isinstance(arg, str) and " " in arg:
                        module, name = arg.split(" ", 1)
                    elif isinstance(arg, str):
                        module, name = arg, ""
                    # GLOBAL/INST also pushes the resolved global onto the stack
                    stack.append(_NONSTR)
                elif nm == "STACK_GLOBAL":
                    # STACK_GLOBAL pops name (top), then module (below it).
                    if len(stack) >= 2:
                        cand_name, cand_module = stack[-1], stack[-2]
                        stack.pop()
                        stack.pop()
                        stack.append(_NONSTR)  # the resulting global object
                        if isinstance(cand_module, str) and isinstance(cand_name, str):
                            module, name = cand_module, cand_name
                if module is not None and _is_dangerous(module, name or ""):
                    hits.append({"module": module, "name": name or "",
                                 "opcode": nm, "reduce": False})
                if nm == "STOP":
                    stopped = True
                    break
        except Exception:
            # malformed/truncated pickle — keep what we have (don't fail-stop)
            break
        if not stopped:
            # genops ran off the end without a STOP; nothing more to resume.
            break
        new = last + 1
        if new <= offset:
            break
        offset = new
    # annotate whether a REDUCE-family invocation appeared anywhere
    if saw_reduce:
        for h in hits:
            h["reduce"] = True
    return hits


def scan_pickles_in_zip(data: bytes) -> list[dict]:
    """Scan EVERY entry of a zip (PyTorch .pt/.pth, joblib) for embedded pickles,
    even if individual entries have a bad CRC (CVE-2025-10156: don't fail-stop)."""
    out: list[dict] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return out
    for info in zf.infolist():
        if info.is_dir():
            continue
        raw = b""
        try:
            raw = zf.read(info.filename)        # validates CRC
        except Exception:
            # bad CRC / corrupt entry — read raw bytes anyway and scan them
            try:
                with zf.open(info, "r") as fh:
                    raw = fh.read()
            except Exception:
                try:
                    raw = _read_raw_local(data, info)
                except Exception:
                    continue
        for h in scan_pickle_bytes(raw):
            h["entry"] = info.filename
            out.append(h)
    return out


def _read_raw_local(data: bytes, info: zipfile.ZipInfo) -> bytes:
    """Best-effort raw read of a zip entry by offset, used only when the normal
    path raised (e.g. bad CRC). Handles STORED and DEFLATED. Returns b'' if it
    can't."""
    start = info.header_offset
    if data[start:start + 4] != b"PK\x03\x04":
        return b""
    n_len = int.from_bytes(data[start + 26:start + 28], "little")
    e_len = int.from_bytes(data[start + 28:start + 30], "little")
    body = start + 30 + n_len + e_len
    if info.compress_type == zipfile.ZIP_STORED:
        return data[body:body + info.file_size]
    if info.compress_type == zipfile.ZIP_DEFLATED:
        try:
            raw_compressed = data[body:body + info.compress_size]
            return zlib.decompress(raw_compressed, -15)  # raw/headerless deflate
        except Exception:
            return b""
    return b""
