# pencheff/modules/rag_scan/module.py
"""Static RAG scan module: connect → manifest → static analyzers + fingerprint."""
from __future__ import annotations

import logging

from pencheff.core.findings import Finding
from pencheff.modules.base import BaseTestModule

from .connectors import GenericRestConnector
from .endpoint_probe import run_rag_endpoint_probe
from .fingerprint import fingerprint
from .manifest import RagManifest, RagSampleChunk
from .poison import run_poison_injection, run_retrieval_hijack
from .query_probes import run_query_probes
from .static_analyzers import baseline_hash, run_all_static


class RagStaticScanModule(BaseTestModule):
    name = "rag_static_scan"
    category = "RAG Security"
    owasp_categories = ["LLM02", "LLM04", "LLM08"]
    description = "Connect to a RAG / vector-DB target and statically analyze its manifest for exposure, secrets, and known vulnerabilities."

    async def run(self, session, http=None, targets=None, config=None) -> list[Finding]:
        cfg = (config or {}).get("rag_config") or {}
        st = cfg.get("source_type")

        if st == "rag_endpoint":
            try:
                return await run_rag_endpoint_probe(session, cfg)
            except Exception as e:
                from pencheff.modules.rag_scan import endpoint_probe as _ep
                _ep.log.warning("rag_endpoint module-level probe failed: %s", e)
                return []

        connector: GenericRestConnector | None = None

        if st == "embedding_artifact":
            items = cfg.get("items") or []
            manifest = RagManifest(
                source_type="embedding_artifact",
                provider=None,
                endpoint="artifact",
                samples=[
                    RagSampleChunk(index="artifact", chunk_id=str(i), text=t)
                    for i, t in enumerate(items)
                ],
            )
        else:
            # managed_vdb / self_hosted_vdb — use the REST connector.
            try:
                connector = GenericRestConnector()
                logging.getLogger(__name__).info("scan_progress: connecting to RAG target")
                manifest = await connector.build_manifest(cfg)
                logging.getLogger(__name__).info("scan_progress: sampled %d items", len(manifest.samples) if manifest.samples else 0)
            except Exception:
                return []

        findings = run_all_static(manifest)
        findings.extend(fingerprint(manifest))
        digest = baseline_hash(manifest)
        for f in findings:
            f.metadata = {**(f.metadata or {}), "manifest_baseline": digest}

        # -- Dynamic query probes (consent-gated, non-fatal) --
        if cfg.get("query_probes") and connector is not None:
            try:
                async def _query_fn(prompt: str) -> list[str]:
                    return await connector.query(prompt)

                probe_findings = await run_query_probes(_query_fn, manifest, cfg)
                findings.extend(probe_findings)
            except Exception:
                pass

            # -- Poison injection probe (consent-gated: requires BOTH query_probes AND poison_injection_opt_in) --
            if cfg.get("poison_injection_opt_in"):
                try:
                    async def _upsert_fn(doc: dict) -> str:
                        return await connector.upsert(doc)

                    async def _delete_fn(doc_id: str) -> None:
                        await connector.delete(doc_id)

                    async def _poison_query_fn(prompt: str) -> list[str]:
                        return await connector.query(prompt)

                    poison_findings = await run_poison_injection(
                        _upsert_fn, _delete_fn, _poison_query_fn, cfg
                    )
                    findings.extend(poison_findings)
                    hijack_findings = await run_retrieval_hijack(
                        _upsert_fn, _delete_fn, _poison_query_fn, cfg
                    )
                    findings.extend(hijack_findings)
                except Exception:
                    pass

        return findings

    def get_techniques(self) -> list[str]:
        return [
            "rag:exposed-db",
            "rag:cross-tenant-leak",
            "rag:secret-at-rest",
            "rag:embedding-inversion-risk",
            "rag:indirect-injection-at-rest",
            "rag:exfil-link-at-rest",
            "rag:retrieval-dominance",
            "rag:known-vuln",
            "rag:kb-poisoning",
            "rag:retrieval-hijack",
        ]
