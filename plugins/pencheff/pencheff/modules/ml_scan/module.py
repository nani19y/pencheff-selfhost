# pencheff/modules/ml_scan/module.py
"""Static ML-model scan module: fetch (bounded, never load) → classify →
pure static analyzers + known-vuln fingerprint. Mirrors RagStaticScanModule."""
from __future__ import annotations

from pencheff.core.findings import Finding
from pencheff.modules.base import BaseTestModule

from .analyzers import run_all_static
from .fetcher import build_manifest
from .fingerprint import fingerprint


class MlStaticScanModule(BaseTestModule):
    name = "ml_static_scan"
    category = "ML Model Security"
    owasp_categories = ["LLM03", "LLM04"]
    description = (
        "Statically inspect a model artifact (pickle opcodes, format safety, "
        "Keras Lambda, known vulns) WITHOUT ever loading or deserializing it."
    )

    async def run(self, session, http=None, targets=None, config=None) -> list[Finding]:
        cfg = (config or {}).get("ml_config") or {}
        try:
            manifest = await build_manifest(cfg)
        except Exception:
            return []
        findings = run_all_static(manifest)
        findings.extend(fingerprint(manifest))
        if manifest.fetch_errors:
            for f in findings:
                f.metadata = {**(f.metadata or {}), "fetch_errors": manifest.fetch_errors}
        return findings

    def get_techniques(self) -> list[str]:
        return [
            "ml:pickle-rce",
            "ml:unsafe-format",
            "ml:keras-lambda",
            "ml:known-vuln",
            "ml:supply-chain",
        ]
