"""Tests for ``pencheff_api.services.triage_llm`` — DeepSeek-backed
AI Triage 2.0. Covers JSON parsing (the failure-prone part) plus
end-to-end invocation against a mocked DeepSeek endpoint.
"""
from __future__ import annotations

import json

import httpx
import pytest

from pencheff_api.services.triage_llm import (
    TriageLLMClient,
    TriageResult,
    _parse_triage_json,
)


# ── JSON parser ──────────────────────────────────────────────────────


def _good_json() -> str:
    return json.dumps({
        "walkthrough":      "User input flows unsanitized into a SQL string.",
        "blast_radius":     "Full DB read access; can pivot to admin.",
        "exploit_scenario": "1. POST /login with q='OR 1=1.\n2. Read response.",
        "fix_outline":      "Use parameterised queries; reject single quotes.",
        "confidence":       "high",
    })


def test_parse_well_formed_response():
    out = _parse_triage_json(_good_json(), model="deepseek-chat",
                             input_tokens=400, output_tokens=120)
    assert isinstance(out, TriageResult)
    assert out.confidence == "high"
    assert "SQL" in out.walkthrough
    assert out.input_tokens == 400


def test_parse_strips_markdown_code_fences():
    """The model sometimes ignores 'no fences' and wraps in ```json."""
    raw = "```json\n" + _good_json() + "\n```"
    out = _parse_triage_json(raw, model="m", input_tokens=0, output_tokens=0)
    assert out is not None and out.confidence == "high"


def test_parse_invalid_confidence_falls_back_to_low():
    raw = json.dumps({
        "walkthrough": "x", "blast_radius": "y", "exploit_scenario": "z",
        "fix_outline": "w", "confidence": "very-confident-actually",
    })
    out = _parse_triage_json(raw, model="m", input_tokens=0, output_tokens=0)
    assert out is not None and out.confidence == "low"


def test_parse_missing_required_field_returns_none():
    raw = json.dumps({
        "walkthrough": "x", "blast_radius": "y",
        # missing exploit_scenario, fix_outline, confidence
    })
    out = _parse_triage_json(raw, model="m", input_tokens=0, output_tokens=0)
    assert out is None


def test_parse_non_string_field_returns_none():
    raw = json.dumps({
        "walkthrough": "x", "blast_radius": "y", "exploit_scenario": "z",
        "fix_outline": ["array", "instead", "of", "string"],
        "confidence": "high",
    })
    out = _parse_triage_json(raw, model="m", input_tokens=0, output_tokens=0)
    assert out is None


def test_parse_garbage_returns_none():
    out = _parse_triage_json("not json at all",
                             model="m", input_tokens=0, output_tokens=0)
    assert out is None


# ── Client end-to-end (mocked DeepSeek) ─────────────────────────────


@pytest.fixture
def mock_deepseek_settings(monkeypatch):
    """Configure the FixLLM settings so ``TriageLLMClient.enabled``
    returns True. Each test installs its own httpx mock."""
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "fix_llm_api_key", "sk-test-key")
    monkeypatch.setattr(s, "fix_llm_base_url", "https://api.deepseek.com/v1")
    monkeypatch.setattr(s, "fix_llm_model", "deepseek-v4-flash")
    monkeypatch.setattr(s, "triage_llm_model", "deepseek-chat")
    monkeypatch.setattr(s, "fix_llm_request_timeout", 30.0)
    return s


def _mock_deepseek_response(monkeypatch, body: str | None = None,
                             status_code: int = 200):
    """Patch httpx.AsyncClient.post to return a fake DeepSeek response."""
    if body is None:
        body = _good_json()

    async def _fake_post(self, url, headers=None, json=None):
        # Build a minimal DeepSeek-shaped response.
        request = httpx.Request("POST", url)
        return httpx.Response(
            status_code=status_code,
            request=request,
            json={
                "choices": [{"message": {"content": body}}],
                "usage": {"prompt_tokens": 250, "completion_tokens": 90},
            },
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post)


@pytest.mark.asyncio
async def test_triage_finding_happy_path(mock_deepseek_settings, monkeypatch):
    _mock_deepseek_response(monkeypatch)
    client = TriageLLMClient()
    result = await client.triage_finding(
        title="SQL injection in /login",
        severity="critical", category="injection",
        endpoint="https://target.example.com/login",
        parameter="q", description="reflected sqli",
        evidence_excerpt="POST /login q=' OR 1=1 → 200 OK",
        cvss_score=9.8, reachability="exploited",
        epss=0.95, kev=True, cwe_id="CWE-89",
        owasp_category="A03",
    )
    assert result is not None
    assert result.confidence == "high"
    assert result.input_tokens == 250
    assert result.output_tokens == 90


@pytest.mark.asyncio
async def test_triage_returns_none_on_http_error(
    mock_deepseek_settings, monkeypatch,
):
    _mock_deepseek_response(monkeypatch, body="server exploded",
                            status_code=500)
    client = TriageLLMClient()
    result = await client.triage_finding(
        title="x", severity="low", category="info",
        endpoint=None, parameter=None, description=None,
        evidence_excerpt="", cvss_score=None,
        reachability=None, epss=None, kev=False,
        cwe_id=None, owasp_category=None,
    )
    assert result is None


@pytest.mark.asyncio
async def test_triage_returns_none_on_malformed_json(
    mock_deepseek_settings, monkeypatch,
):
    _mock_deepseek_response(monkeypatch, body="not even close to json")
    client = TriageLLMClient()
    result = await client.triage_finding(
        title="x", severity="low", category="info",
        endpoint=None, parameter=None, description=None,
        evidence_excerpt="", cvss_score=None,
        reachability=None, epss=None, kev=False,
        cwe_id=None, owasp_category=None,
    )
    assert result is None


@pytest.mark.asyncio
async def test_triage_disabled_when_no_api_key(monkeypatch):
    from pencheff_api.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "fix_llm_api_key", "")
    client = TriageLLMClient()
    assert client.enabled is False
    result = await client.triage_finding(
        title="x", severity="low", category="info",
        endpoint=None, parameter=None, description=None,
        evidence_excerpt="", cvss_score=None,
        reachability=None, epss=None, kev=False,
        cwe_id=None, owasp_category=None,
    )
    assert result is None
