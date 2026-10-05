"""Tests for the engagement-scoped threat-model service.

Covers:
  * generate_threat_model — STRIDE / DREAD output shape, asset
    inference (target URL → asset type), explicit asset names, scoring.
  * module_priority_bias — STRIDE-only fallback, DREAD category-score
    ranking, deterministic order, no-model passthrough.
  * render_markdown — STRIDE table + DREAD top-threats projection.
"""

from __future__ import annotations

import pytest

from pencheff_api.services.threat_model import (
    CATEGORY_MODULE_BIAS,
    STRIDE_MATRIX,
    generate_threat_model,
    module_priority_bias,
    render_markdown,
)


# ─── generate_threat_model ──────────────────────────────────────────────


def test_stride_for_webapp_target_has_six_categories():
    out = generate_threat_model(target_url="https://example.com")
    assert out["method"] == "STRIDE"
    assert any(a["type"] == "webapp" for a in out["assets"])
    cats = {row["category"] for row in out["table"]}
    # STRIDE has six categories — every one must show up for webapp.
    assert cats == {
        "Spoofing", "Tampering", "Repudiation",
        "Information Disclosure", "Denial of Service", "Elevation of Privilege",
    }


def test_stride_threats_carry_default_mitigations():
    out = generate_threat_model(target_url="https://example.com")
    spoofing = next(r for r in out["table"] if r["category"] == "Spoofing")
    assert "MFA" in " ".join(spoofing["mitigations"])  # MFA is a default mitigation


def test_target_url_with_api_path_infers_api_asset():
    """A URL containing /api or graphql should pick the API matrix —
    different threat catalogue (BOLA, GraphQL N+1, etc)."""
    out = generate_threat_model(target_url="https://api.example.com/graphql")
    types = {a["type"] for a in out["assets"]}
    assert types == {"api"}
    # API matrix has its own threats — verify one survived through to output.
    titles = {row["category"] for row in out["table"]}
    assert "Tampering" in titles  # API matrix has Tampering with GraphQL items
    api_tamper = next(r for r in out["table"] if r["category"] == "Tampering")
    assert any("GraphQL" in t for t in api_tamper["threats"])


def test_target_url_with_s3_path_infers_cloud_asset():
    out = generate_threat_model(target_url="https://my-bucket.s3.amazonaws.com")
    assert {a["type"] for a in out["assets"]} == {"cloud"}


def test_explicit_asset_types_override_inference():
    out = generate_threat_model(
        target_url="https://example.com",
        asset_types=["mobile", "network"],
    )
    types = [a["type"] for a in out["assets"]]
    assert types == ["mobile", "network"]
    cats = {row["category"] for row in out["table"]}
    # Both matrices must have populated.
    assert "Spoofing" in cats


def test_explicit_asset_names_kept_alongside_types():
    out = generate_threat_model(
        target_url=None,
        asset_names=["payments-api", "admin-console"],
        asset_types=["api", "webapp"],
    )
    names = [a["name"] for a in out["assets"]]
    assert names == ["payments-api", "admin-console"]
    types = [a["type"] for a in out["assets"]]
    assert types == ["api", "webapp"]


def test_no_target_falls_back_to_single_webapp():
    """Defensive: caller hands us nothing useful → still produces a valid
    model so the UI doesn't have to special-case empty input."""
    out = generate_threat_model(target_url=None)
    assert len(out["assets"]) == 1
    assert out["assets"][0]["type"] == "webapp"


# ─── DREAD scoring ──────────────────────────────────────────────────────


def test_dread_method_emits_per_threat_scores():
    out = generate_threat_model(
        target_url="https://example.com", method="dread"
    )
    assert out["method"] == "DREAD"
    assert "threats" in out
    assert "table" not in out  # STRIDE-only field
    # Every threat row carries the five DREAD scores + total.
    sample = out["threats"][0]
    for k in ("damage", "reproducibility", "exploitability",
              "affected_users", "discoverability", "score", "priority"):
        assert k in sample
    # Score is in [1, 10]; priority in {critical, high, medium, low}.
    assert 1 <= sample["score"] <= 10
    assert sample["priority"] in {"critical", "high", "medium", "low"}


def test_dread_category_scores_are_per_category_averages():
    """category_scores is what the adaptive-scan biaser reads. It must
    aggregate one number per category, not per individual threat."""
    out = generate_threat_model(
        target_url="https://example.com", method="dread"
    )
    cs = out["category_scores"]
    assert set(cs.keys()) <= {
        "Spoofing", "Tampering", "Repudiation",
        "Information Disclosure", "Denial of Service", "Elevation of Privilege",
    }
    for v in cs.values():
        assert 1 <= v <= 10


def test_dread_priority_thresholds():
    """Score → priority mapping must match the documented bands."""
    out = generate_threat_model(
        target_url="https://example.com", method="dread"
    )
    for t in out["threats"]:
        s = t["score"]
        p = t["priority"]
        if s >= 8:
            assert p == "critical"
        elif s >= 6:
            assert p == "high"
        elif s >= 4:
            assert p == "medium"
        else:
            assert p == "low"


# ─── module_priority_bias ──────────────────────────────────────────────


def test_no_model_returns_empty_bias():
    """No threat model on the engagement → caller leaves its module
    order alone (empty bias = passthrough)."""
    assert module_priority_bias(None) == []
    assert module_priority_bias({}) == []


def test_bias_returns_module_names_in_priority_order():
    """Top-priority category's modules must appear before lower-priority
    categories. Categories not in CATEGORY_MODULE_BIAS contribute
    nothing (defensive: avoids surfacing bogus module names)."""
    model = {
        "method": "DREAD",
        "category_scores": {
            "Information Disclosure": 9.2,  # rank 1
            "Tampering": 7.0,               # rank 2
            "Spoofing": 5.0,                # rank 3
        },
    }
    bias = module_priority_bias(model)
    info_disclosure_modules = CATEGORY_MODULE_BIAS["Information Disclosure"]
    tampering_modules = CATEGORY_MODULE_BIAS["Tampering"]
    # First module must come from the top-ranked category.
    assert bias[0] in info_disclosure_modules
    # All Information Disclosure modules appear before any Tampering-only ones.
    info_idx = max(bias.index(m) for m in info_disclosure_modules if m in bias)
    only_tamper = [m for m in tampering_modules if m not in info_disclosure_modules]
    if only_tamper:
        first_tamper_only = min(bias.index(m) for m in only_tamper if m in bias)
        assert info_idx < first_tamper_only


def test_bias_dedupes_modules_shared_across_categories():
    """A module mapped under more than one STRIDE category appears once,
    at the position of its highest-ranked category."""
    model = {
        "method": "DREAD",
        "category_scores": {
            "Information Disclosure": 9.0,  # has scan_infrastructure
            "Repudiation": 8.0,             # also has scan_infrastructure
        },
    }
    bias = module_priority_bias(model)
    assert bias.count("scan_infrastructure") == 1


def test_stride_only_model_produces_useful_bias():
    """A STRIDE-only model has no per-category scores. The bias still
    produces a deterministic order using the default DREAD weights as
    a tie-breaker (so a basic STRIDE model is not useless).

    With the calibrated defaults in :data:`DEFAULT_DREAD`, Information
    Disclosure scores highest (8.0+ on Discoverability), so its modules
    should lead the bias.
    """
    model = generate_threat_model(target_url="https://example.com", method="stride")
    bias = module_priority_bias(model)
    assert len(bias) > 0
    info_disc_modules = CATEGORY_MODULE_BIAS["Information Disclosure"]
    assert bias[0] in info_disc_modules


# ─── render_markdown ────────────────────────────────────────────────────


def test_render_stride_includes_table_with_pipe_syntax():
    """Renderer must emit GFM tables — the web Markdown viewer renders
    them as actual HTML tables, not plain text."""
    model = generate_threat_model(target_url="https://example.com")
    md = render_markdown(model)
    assert md.startswith("# STRIDE Threat Model")
    assert "| Asset | Category | Threats | Mitigations |" in md
    assert "| --- | --- | --- | --- |" in md


def test_render_dread_includes_top_threats_table_and_category_scores():
    model = generate_threat_model(target_url="https://example.com", method="dread")
    md = render_markdown(model)
    assert "# DREAD Threat Model" in md
    assert "## Top threats" in md
    assert "## Category scores" in md
    # Top threats table is bounded — never dump the full DREAD set.
    threat_lines = [l for l in md.splitlines() if l.startswith("| ") and "Threat" not in l and "---" not in l]
    assert len(threat_lines) <= 25


def test_render_handles_empty_or_partial_model():
    """JSON-shape-tolerant: a partial model (e.g. just a method name)
    must render without raising."""
    assert render_markdown({}) == ""
    md = render_markdown({"method": "STRIDE"})
    assert md.startswith("# STRIDE Threat Model")


# ─── Matrix integrity ──────────────────────────────────────────────────


def test_every_asset_type_has_all_six_stride_categories():
    """Defensive matrix-completeness check — if someone adds a new
    asset type and forgets a category, that asset's threat model would
    silently miss attacks. Catch it here."""
    expected = {
        "Spoofing", "Tampering", "Repudiation",
        "Information Disclosure", "Denial of Service", "Elevation of Privilege",
    }
    for asset_type, matrix in STRIDE_MATRIX.items():
        assert set(matrix.keys()) == expected, (
            f"asset type {asset_type!r} is missing STRIDE categories"
        )
