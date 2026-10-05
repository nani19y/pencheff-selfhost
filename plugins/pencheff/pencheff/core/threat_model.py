"""Deterministic STRIDE / DREAD threat model generator.

Reads scope assets and produces structured threat tables. No LLM —
the rubric lives in ``data/stride_dread.json``.

STRIDE: Spoofing, Tampering, Repudiation, Information Disclosure,
        Denial of Service, Elevation of Privilege.
DREAD:  Damage, Reproducibility, Exploitability, Affected Users, Discoverability
        (each scored 1–10, total / 5 = priority).
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_FILE = Path(__file__).resolve().parents[1] / "data" / "stride_dread.json"


@lru_cache(maxsize=1)
def _rubric() -> dict[str, Any]:
    if not DATA_FILE.exists():
        return {"stride": {}, "dread_template": {}}
    return json.loads(DATA_FILE.read_text())


def stride(asset: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a STRIDE table for one asset."""
    out: list[dict[str, Any]] = []
    rubric = _rubric().get("stride", {})
    asset_type = asset.get("type", "webapp")
    matrix = rubric.get(asset_type, rubric.get("webapp", {}))
    for category, examples in matrix.items():
        out.append({
            "asset": asset.get("name", asset_type),
            "category": category,
            "threats": list(examples) if isinstance(examples, list) else [examples],
            "mitigations": _default_mitigations(category),
        })
    return out


def dread(threat: str, *, damage: int = 5, reproducibility: int = 5,
          exploitability: int = 5, affected: int = 5, discoverability: int = 5) -> dict[str, Any]:
    score = (damage + reproducibility + exploitability + affected + discoverability) / 5.0
    return {
        "threat": threat,
        "damage": damage,
        "reproducibility": reproducibility,
        "exploitability": exploitability,
        "affected_users": affected,
        "discoverability": discoverability,
        "score": round(score, 2),
        "priority": _priority(score),
    }


def model_for_scope(scope: dict[str, Any], method: str = "stride") -> dict[str, Any]:
    """Generate a complete threat model for an engagement scope."""
    assets = _scope_to_assets(scope)
    if method.lower() == "dread":
        threats = []
        for a in assets:
            for row in stride(a):
                for thr in row["threats"]:
                    threats.append(dread(f"{a['name']}: {thr}"))
        return {"method": "DREAD", "assets": assets, "threats": threats}
    return {
        "method": "STRIDE",
        "assets": assets,
        "table": [row for a in assets for row in stride(a)],
    }


def _scope_to_assets(scope: dict[str, Any]) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    for u in scope.get("urls", []):
        assets.append({"name": u, "type": "webapp"})
    for d in scope.get("domains", []):
        assets.append({"name": d, "type": "webapp"})
    for r in scope.get("ip_ranges", []):
        assets.append({"name": r, "type": "network"})
    for c in scope.get("cloud_accounts", []):
        assets.append({"name": c, "type": "cloud"})
    if not assets:
        assets.append({"name": scope.get("client", "target"), "type": "webapp"})
    return assets


def _priority(score: float) -> str:
    if score >= 8:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


_MIT = {
    "Spoofing": ["Strong authentication (MFA)", "Mutual TLS", "Signed tokens (JWT, SAML)"],
    "Tampering": ["Input validation", "Integrity checks (HMAC)", "WAF + content security policy"],
    "Repudiation": ["Audit logging", "Non-repudiation signatures", "Tamper-evident logs"],
    "Information Disclosure": ["TLS everywhere", "Field-level encryption", "Output filtering"],
    "Denial of Service": ["Rate limiting", "Autoscaling", "WAF circuit breakers"],
    "Elevation of Privilege": ["Least-privilege RBAC", "Privilege boundaries", "Authorization checks per request"],
}


def _default_mitigations(category: str) -> list[str]:
    return _MIT.get(category, [])
