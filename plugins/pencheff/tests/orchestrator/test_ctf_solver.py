"""CTF challenge classifier."""

from __future__ import annotations

from pencheff.modules.ctf.solver import (
    candidate_tools,
    classify_file,
    classify_text,
)


def test_classify_text_base64():
    kind = classify_text("U29tZUNvb2xCYXNlNjRTdHJpbmc=")
    assert kind is not None
    assert kind.name == "base64"


def test_classify_text_morse():
    kind = classify_text(".... . .-.. .-.. ---")
    assert kind is not None
    assert kind.name == "morse"


def test_classify_text_hex():
    kind = classify_text("deadbeefcafe")
    assert kind is not None
    assert kind.name == "hex"


def test_classify_text_flag_obvious():
    kind = classify_text("FLAG{actually_the_flag}")
    assert kind is not None
    assert kind.name == "flag_obvious"


def test_classify_file_png(tmp_path):
    p = tmp_path / "x.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    kind = classify_file(p)
    assert kind is not None
    assert kind.name == "stego_image_png"


def test_classify_file_jpeg(tmp_path):
    p = tmp_path / "x.jpg"
    p.write_bytes(b"\xff\xd8\xff" + b"\x00" * 16)
    kind = classify_file(p)
    assert kind is not None
    assert kind.name == "stego_image_jpeg"


def test_candidate_tools_returns_iterable():
    from pencheff.modules.ctf.solver import ChallengeKind
    kind = ChallengeKind(name="stego_image_png", rationale="png")
    tools = list(candidate_tools(kind))
    assert "zsteg" in tools
