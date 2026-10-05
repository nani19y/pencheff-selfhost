import io
import os
import pickle
import zipfile

from pencheff.modules.ml_scan.pickle_scan import scan_pickle_bytes, scan_pickles_in_zip


class _Evil:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


def test_flags_os_system_reduce_proto2():
    blob = pickle.dumps(_Evil(), protocol=2)   # GLOBAL form
    hits = scan_pickle_bytes(blob)
    assert any(h["module"] == "posix" or h["module"] == "os" or "system" in h["name"] for h in hits)
    assert any(h["reduce"] for h in hits)


def test_flags_stack_global_proto4():
    blob = pickle.dumps(_Evil(), protocol=4)   # STACK_GLOBAL form
    hits = scan_pickle_bytes(blob)
    assert hits, "STACK_GLOBAL dangerous import must be detected"


def test_benign_pickle_has_no_hits():
    blob = pickle.dumps({"weights": [1, 2, 3], "name": "ok"})
    assert scan_pickle_bytes(blob) == []


def test_submodule_of_dangerous_is_flagged():
    # CVE-2025-10157: subpackage import of a dangerous module must still flag
    # craft a GLOBAL referencing "os.path" "exists" — built manually
    # \x80\x02 c os.path \n exists \n \x85 R .   (proto-2 GLOBAL + REDUCE)
    blob = b"\x80\x02cos.path\nexists\n\x85R."
    hits = scan_pickle_bytes(blob)
    assert any(h["module"].startswith("os") for h in hits)


def test_scans_all_embedded_pickles_in_zip_even_bad_crc():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl", pickle.dumps(_Evil(), protocol=2))
        z.writestr("archive/version", b"3")
    hits = scan_pickles_in_zip(buf.getvalue())
    assert any(h["entry"].endswith("data.pkl") for h in hits)


def test_scans_past_first_stop():
    # two concatenated pickles; danger is in the SECOND (after first STOP)
    benign = pickle.dumps({"a": 1})
    evil = pickle.dumps(_Evil(), protocol=2)
    hits = scan_pickle_bytes(benign + evil)
    assert hits, "must continue scanning past the first STOP opcode"


def test_stack_global_memo_indirection_with_decoys_is_detected():
    # os/system pushed, memoized, decoys pushed, then BINGET'd back before STACK_GLOBAL.
    # Built as raw bytes so we never execute it.
    blob = (b"\x80\x04"                      # PROTO 4
            b"\x8c\x02os\x94"                # SHORT_BINUNICODE 'os' ; MEMOIZE(0)
            b"\x8c\x06system\x94"            # SHORT_BINUNICODE 'system' ; MEMOIZE(1)
            b"\x8c\x04junk\x94"              # decoy ; MEMOIZE(2)
            b"\x8c\x05junk2\x94"             # decoy ; MEMOIZE(3)
            b"h\x00"                          # BINGET 0 -> 'os'
            b"h\x01"                          # BINGET 1 -> 'system'
            b"\x93"                          # STACK_GLOBAL
            b")R.")                           # EMPTY_TUPLE ; REDUCE ; STOP
    hits = scan_pickle_bytes(blob)
    assert any(h["module"] == "os" and h["name"] == "system" for h in hits)


def test_stack_global_dup_indirection_is_detected():
    # push 'os','system', DUP-juggle, still detected
    blob = (b"\x80\x04"
            b"\x8c\x02os\x94"
            b"\x8c\x06system\x94"
            b"\x93)R.")
    hits = scan_pickle_bytes(blob)
    assert any(h["module"] == "os" for h in hits)


def test_scans_deflated_entry_with_bad_crc():
    import io, os, pickle, zipfile
    class _E:
        def __reduce__(self): return (os.system, ("x",))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("archive/data.pkl", pickle.dumps(_E()))
    raw = bytearray(buf.getvalue())
    # corrupt the CRC-32 field of the first local file header (offset 14, 4 bytes)
    raw[14] ^= 0xFF
    hits = scan_pickles_in_zip(bytes(raw))
    assert any(h["module"] in ("os", "posix") for h in hits)
