"""Tests for the NVD enrichment path added to ``cve_feed`` + the
structured-field surface added to SCA findings."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from pencheff.core import cve_feed as cf
from pencheff.core.cve_feed import (
    CveFeed,
    CveInfo,
    NvdEnrichment,
    _extract_nvd_cvss,
    _parse_nvd_cve,
)
from pencheff.core.findings import Finding
from pencheff.modules.sca.dependency_scan import _vuln_to_finding, scan_deps
from pencheff.modules.sca.manifest_parsers import Dep
from pencheff.core.cve_feed import DepVuln


@pytest.fixture
def tmp_feed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CveFeed:
    """Isolated CveFeed pointed at a fresh SQLite DB so tests can't
    pollute the user's ~/.pencheff/cve_cache.db."""
    monkeypatch.setattr(cf, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(cf, "CACHE_DB", tmp_path / "cve_cache.db")
    monkeypatch.setattr(cf, "_feed", None)  # reset singleton
    feed = CveFeed()
    yield feed
    feed.close()


# ─── _parse_nvd_cve / _extract_nvd_cvss ─────────────────────────────────


def test_parse_nvd_extracts_cwe_cpe_cvss():
    """The NVD 2.0 CVE shape is verbose — the parser must pick out the
    fields findings actually use without choking on the surrounding noise."""
    cve_obj = {
        "id": "CVE-2024-1234",
        "descriptions": [{"lang": "en", "value": "Reflected XSS in widget"}],
        "weaknesses": [
            {"description": [{"value": "CWE-79"}, {"value": "CWE-352"}]},
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
                            },
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:a:acme:widget:2.0:*:*:*:*:*:*:*",
                            },
                        ]
                    }
                ]
            }
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 8.6,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        "baseSeverity": "HIGH",
                    }
                }
            ]
        },
        "published": "2024-01-15T00:00:00.000",
    }
    out = _parse_nvd_cve("CVE-2024-1234", cve_obj)
    assert out.cwe_ids == ["CWE-79", "CWE-352"]
    assert out.cpe_uris == ["cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"]
    # Non-vulnerable entry is filtered out — important so the agent doesn't
    # get told a fixed version is exploitable.
    assert "cpe:2.3:a:acme:widget:2.0:*:*:*:*:*:*:*" not in out.cpe_uris
    assert out.nvd_cvss_score == 8.6
    assert out.nvd_cvss_severity == "high"
    assert out.primary_url == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    assert out.description == "Reflected XSS in widget"


def test_extract_cvss_prefers_v31_over_v2():
    metrics = {
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "vectorString": "v2vec"}}],
        "cvssMetricV31": [
            {"cvssData": {"baseScore": 9.8, "vectorString": "v31vec", "baseSeverity": "CRITICAL"}}
        ],
    }
    score, vector, severity = _extract_nvd_cvss(metrics)
    assert score == 9.8
    assert vector == "v31vec"
    assert severity == "critical"


def test_extract_cvss_falls_through_when_v31_missing_score():
    metrics = {
        "cvssMetricV31": [{"cvssData": {}}],
        "cvssMetricV30": [
            {"cvssData": {"baseScore": 7.5, "vectorString": "v30vec", "baseSeverity": "HIGH"}}
        ],
    }
    score, _, severity = _extract_nvd_cvss(metrics)
    assert score == 7.5
    assert severity == "high"


# ─── CveInfo.primary_advisory_url ───────────────────────────────────────


def test_primary_advisory_url_prefers_nvd_when_enriched():
    info = CveInfo(cve="CVE-2024-1234")
    info.nvd = NvdEnrichment(
        cve="CVE-2024-1234",
        primary_url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
    )
    assert info.primary_advisory_url == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"


def test_primary_advisory_url_falls_back_to_canonical_nvd_link():
    info = CveInfo(cve="CVE-2024-9999")
    assert info.primary_advisory_url == "https://nvd.nist.gov/vuln/detail/CVE-2024-9999"


def test_primary_advisory_url_none_for_ghsa_alias():
    info = CveInfo(cve="GHSA-aaaa-bbbb-cccc")
    assert info.primary_advisory_url is None


# ─── nvd_enrich + caching ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_nvd_enrich_caches_first_call(tmp_feed, monkeypatch):
    """First call hits the network; second call must NOT — the SQLite
    cache row should serve it back."""
    sample = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "x"}],
                    "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                    "configurations": [],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "vectorString": "v"}}]},
                    "published": "2024-01-15T00:00:00.000",
                }
            }
        ]
    }
    mock_client = AsyncMock()
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: sample
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("pencheff.core.cve_feed.httpx.AsyncClient", return_value=mock_client):
        out1 = await tmp_feed.nvd_enrich("CVE-2024-1234")
    assert out1 is not None
    assert out1.cwe_ids == ["CWE-79"]

    # Second call must NOT touch the network — patch with a side_effect
    # that fails if invoked.
    failing = AsyncMock(side_effect=AssertionError("network was called"))
    with patch("pencheff.core.cve_feed.httpx.AsyncClient", failing):
        out2 = await tmp_feed.nvd_enrich("CVE-2024-1234")
    assert out2 is not None
    assert out2.cwe_ids == ["CWE-79"]


@pytest.mark.asyncio
async def test_nvd_enrich_rejects_non_cve_ids(tmp_feed):
    out = await tmp_feed.nvd_enrich("GHSA-aaaa-bbbb-cccc")
    assert out is None


@pytest.mark.asyncio
async def test_nvd_enrich_swallows_network_failure(tmp_feed):
    """A 500 from NVD must NOT raise — SCA scans always run offline-tolerant."""
    mock_client = AsyncMock()
    mock_response = AsyncMock()
    mock_response.status_code = 503
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    with patch("pencheff.core.cve_feed.httpx.AsyncClient", return_value=mock_client):
        out = await tmp_feed.nvd_enrich("CVE-2024-1234")
    assert out is None


def test_nvd_cache_expires_after_ttl(tmp_feed):
    """A row older than NVD_CACHE_TTL_DAYS must NOT be returned — fresh
    enrichment can pull updated CWE links / advisory URLs."""
    stale_ts = (datetime.now(timezone.utc) - timedelta(days=cf.NVD_CACHE_TTL_DAYS + 1)).isoformat()
    payload = {
        "cve": "CVE-2024-OLD",
        "cwe_ids": ["CWE-1"],
        "cpe_uris": [],
        "nvd_cvss_score": None,
        "nvd_cvss_vector": None,
        "nvd_cvss_severity": None,
        "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-OLD",
        "published": None,
        "description": None,
    }
    tmp_feed.conn.execute(
        "INSERT INTO nvd_cache VALUES (?, ?, ?)",
        ("CVE-2024-OLD", json.dumps(payload), stale_ts),
    )
    tmp_feed.conn.commit()
    assert tmp_feed._load_cached_nvd("CVE-2024-OLD") is None


@pytest.mark.asyncio
async def test_nvd_api_key_sent_when_set(tmp_feed, monkeypatch):
    """The NVD_API_KEY env var must be propagated as an apiKey header so
    operators get the higher rate limit they paid for."""
    monkeypatch.setenv("NVD_API_KEY", "test-key-abc")
    captured: dict[str, dict[str, str]] = {}

    sample = {"vulnerabilities": []}

    class _Capturing:
        def __init__(self, *a, **kw):
            captured["headers"] = dict(kw.get("headers") or {})

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        async def get(self, *_a, **_kw):
            class _R:
                status_code = 200

                def json(self):
                    return sample

            return _R()

    with patch("pencheff.core.cve_feed.httpx.AsyncClient", _Capturing):
        await tmp_feed.nvd_enrich("CVE-2024-1234")
    assert captured["headers"].get("apiKey") == "test-key-abc"


# ─── _vuln_to_finding surfaces structured fields ────────────────────────


def _make_dep_vuln(*, with_nvd: bool = True, with_kev: bool = True) -> tuple[Dep, DepVuln]:
    nvd = (
        NvdEnrichment(
            cve="CVE-2024-1234",
            cwe_ids=["CWE-79", "CWE-352"],
            primary_url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
            nvd_cvss_score=8.1,
            nvd_cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        )
        if with_nvd
        else None
    )
    info = CveInfo(
        cve="CVE-2024-1234",
        epss=0.42,
        epss_percentile=0.95,
        kev=with_kev,
        kev_short_desc="Active exploitation in the wild" if with_kev else None,
        kev_due_date="2024-02-01" if with_kev else None,
        nvd=nvd,
    )
    dep = Dep(
        name="lodash", version="4.17.20", ecosystem="npm",
        source_file="/repo/package.json",
    )
    vuln = DepVuln(
        id="CVE-2024-1234",
        summary="Prototype pollution",
        severity="high",
        cvss_score=7.4,
        cvss_vector="CVSS:3.1/...",
        affected_versions=["<4.17.21"],
        fixed_versions=["4.17.21"],
        references=["https://github.com/lodash/lodash/security/advisories/GHSA-..."],
        cve_info=info,
    )
    return dep, vuln


def test_finding_surfaces_structured_metadata():
    """Every field a downstream consumer (autofix, dashboard, prioritisation)
    needs must live on ``Finding.metadata`` as a structured value, not
    embedded in the description text."""
    dep, vuln = _make_dep_vuln()
    f = _vuln_to_finding(dep, vuln, manifest_rel="package.json")
    md = f.metadata
    assert md["advisory_id"] == "CVE-2024-1234"
    assert md["epss"] == 0.42
    assert md["epss_percentile"] == 0.95
    assert md["kev"] is True
    assert md["kev_short_desc"] == "Active exploitation in the wild"
    assert md["cwe_ids"] == ["CWE-79", "CWE-352"]
    assert md["advisory_url"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    assert md["nvd_cvss_score"] == 8.1
    assert md["fix_version"] == "4.17.21"
    assert md["package"] == "lodash"


def test_finding_promotes_advisory_url_to_first_reference():
    """Renderers (DOCX, PR comment, finding card) link to the first
    reference. We want NVD on top, not the OSV record."""
    dep, vuln = _make_dep_vuln()
    f = _vuln_to_finding(dep, vuln, manifest_rel="package.json")
    assert f.references[0] == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"


def test_finding_uses_first_cwe_as_cwe_id():
    """The Finding has a single ``cwe_id`` field (legacy contract).
    We pick the primary CWE for that and keep the full list in metadata."""
    dep, vuln = _make_dep_vuln()
    f = _vuln_to_finding(dep, vuln)
    assert f.cwe_id == "CWE-79"


def test_finding_works_without_nvd_enrichment():
    """No NVD data → no CWE field, but EPSS/KEV from local cache still
    propagate. Offline-tolerant."""
    dep, vuln = _make_dep_vuln(with_nvd=False)
    f = _vuln_to_finding(dep, vuln)
    assert f.cwe_id is None
    assert f.metadata["cwe_ids"] == []
    # advisory_url still falls back to the canonical NVD URL.
    assert f.metadata["advisory_url"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    assert f.metadata["epss"] == 0.42
    assert f.metadata["kev"] is True


def test_finding_no_cve_info_at_all():
    """OSV returned a vuln but EPSS/KEV/NVD never resolved (offline run).
    Finding should still come out cleanly with empty structured fields."""
    dep = Dep(name="left-pad", version="0.0.1", ecosystem="npm", source_file="package.json")
    vuln = DepVuln(
        id="GHSA-aaaa-bbbb-cccc",
        summary="something",
        severity="medium",
        affected_versions=["<0.1.0"],
        fixed_versions=["0.1.0"],
        references=["https://github.com/example/advisory"],
        cve_info=None,
    )
    f = _vuln_to_finding(dep, vuln)
    md = f.metadata
    assert md["epss"] is None
    assert md["kev"] is False
    assert md["cwe_ids"] == []
    assert md["advisory_url"] is None  # GHSA — no canonical NVD URL
    assert f.cwe_id is None
    assert f.references == ["https://github.com/example/advisory"]
