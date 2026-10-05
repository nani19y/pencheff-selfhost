#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Convert Nuclei (ProjectDiscovery) YAML templates → Pencheff Pulse JSON.

Upstream: https://github.com/projectdiscovery/nuclei-templates  (MIT).
ProjectDiscovery's MIT license permits redistribution with attribution
preserved; every converted template carries a ``__nuclei_source`` /
``__attribution`` pair on its top-level metadata so downstream
consumers can reproduce the citation.

Nuclei's HTTP template subset maps cleanly onto Pulse's:

    nuclei                     | pulse
    ---------------------------+---------------------------
    info.name                  | name
    info.severity              | severity
    info.description           | description
    info.remediation           | remediation
    info.tags                  | tags
    info.reference             | references
    info.classification.cve-id | cves
    requests[]                 | requests[]
    matchers[]                 | matchers[]
    extractors[]               | extractors[]

Unsupported template kinds (network / dns / file / headless) are
*skipped*, not silently coerced — Pulse covers HTTP only and
incorrectly mapping them would produce broken probes.

Usage:

    # Bulk-convert one Nuclei template directory.
    python tools/nuclei2pulse.py \\
        --input /path/to/nuclei-templates/http/cves/ \\
        --output bench/rules/community/pulse/

    # Single file (useful for ad-hoc imports).
    python tools/nuclei2pulse.py \\
        --input /path/to/template.yaml \\
        --output bench/rules/community/pulse/

The converter does NOT scrape upstream over the network — pass a
directory you already have on disk. The CI workflow at
``.github/workflows/community-rules.yml`` (future) will clone the
upstream repo, run the converter, and commit the output as part of
the community rules refresh.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover — yaml is in the plugin extras
    print(
        "error: PyYAML is required (pip install pyyaml).",
        file=sys.stderr,
    )
    sys.exit(1)

NUCLEI_LICENSE = "MIT"
NUCLEI_ATTRIBUTION = (
    "Nuclei templates © ProjectDiscovery, Inc. — MIT — "
    "https://github.com/projectdiscovery/nuclei-templates"
)

# Pulse-supported severities. Nuclei's `unknown` collapses to `info`.
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "info",
}


def _hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]


def convert_one(nuclei: dict[str, Any], source_path: str) -> dict[str, Any] | None:
    """Convert one Nuclei template dict to a Pulse template dict.

    Returns ``None`` for templates Pulse can't represent (anything
    that isn't ``http`` / ``requests``).
    """
    template_id = nuclei.get("id")
    if not template_id:
        return None
    info = nuclei.get("info") or {}
    requests = nuclei.get("http") or nuclei.get("requests") or []
    if not requests:
        return None  # network / dns / file / headless — skip

    severity = _SEVERITY_MAP.get(
        str(info.get("severity") or "info").lower(), "info",
    )
    classification = info.get("classification") or {}
    raw_cves = classification.get("cve-id") or []
    if isinstance(raw_cves, str):
        raw_cves = [raw_cves]
    raw_refs = info.get("reference") or []
    if isinstance(raw_refs, str):
        raw_refs = [raw_refs]
    raw_tags = info.get("tags") or []
    if isinstance(raw_tags, str):
        raw_tags = [t.strip() for t in raw_tags.split(",") if t.strip()]

    pulse = {
        "id": f"nuclei-{template_id}",
        "name": info.get("name") or template_id,
        "severity": severity,
        "description": (info.get("description") or "").strip(),
        "remediation": (info.get("remediation") or "").strip(),
        "tags": list(raw_tags),
        "references": [str(u) for u in raw_refs if u],
        "cves": [str(c).upper() for c in raw_cves if c],
        "requests": _coerce_requests(requests),
        "classification": classification,
        "author": info.get("author") or "ProjectDiscovery",
        # Pulse-specific provenance: documented redirect chain back to
        # the upstream license + attribution.
        "__nuclei_source": source_path,
        "__attribution": NUCLEI_ATTRIBUTION,
        "__license": NUCLEI_LICENSE,
        "__imported_at": datetime.now(timezone.utc).isoformat(),
        # ``signed`` stays False — community-rule signing is a Phase 4
        # workstream; until then operators opt in via
        # ``--require-signed=False`` (the engine default).
        "signed": False,
    }
    return pulse


def _coerce_requests(requests: Any) -> list[dict[str, Any]]:
    """Best-effort copy of the request list.

    Pulse's request schema is structurally similar enough to Nuclei's
    that a deep-copy round-trip works for most simple templates. The
    handful of fields Pulse doesn't recognise (``stop-at-first-match``,
    ``redirects``) are passed through verbatim — Pulse's parser
    ignores unknown keys at present.
    """
    if isinstance(requests, dict):
        return [_coerce_request_block(requests)]
    if isinstance(requests, list):
        return [_coerce_request_block(r) for r in requests if isinstance(r, dict)]
    return []


def _coerce_request_block(block: dict[str, Any]) -> dict[str, Any]:
    """Pass through verbatim, normalising field names where they
    differ. Nuclei's ``method`` / ``path`` / ``raw`` / ``matchers`` /
    ``extractors`` are already valid Pulse field names."""
    return dict(block)


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert Nuclei templates to Pulse JSON.")
    parser.add_argument(
        "--input", required=True,
        help="Path to a Nuclei template file or directory.",
    )
    parser.add_argument(
        "--output", required=True,
        help="Output directory for converted Pulse JSON files.",
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Maximum number of templates to convert (0 = no limit).",
    )
    args = parser.parse_args()

    inp = Path(args.input).resolve()
    out_dir = Path(args.output).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    files: list[Path]
    if inp.is_file():
        files = [inp]
    elif inp.is_dir():
        files = sorted(list(inp.rglob("*.yaml")) + list(inp.rglob("*.yml")))
    else:
        print(f"error: --input {inp} not found", file=sys.stderr)
        return 1

    converted = 0
    skipped = 0
    errors = 0
    for f in files:
        if args.limit and converted >= args.limit:
            break
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            errors += 1
            print(f"  parse error {f}: {exc}", file=sys.stderr)
            continue
        if not isinstance(data, dict):
            skipped += 1
            continue
        pulse = convert_one(data, source_path=str(f))
        if pulse is None:
            skipped += 1
            continue
        # Group by upstream template id to keep diffs small.
        out_path = out_dir / f"nuclei-{data['id']}.json"
        out_path.write_text(
            json.dumps(pulse, indent=2, sort_keys=True), encoding="utf-8",
        )
        converted += 1

    summary = {
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "input": str(inp),
        "output": str(out_dir),
        "converted": converted,
        "skipped": skipped,
        "errors": errors,
        "license": NUCLEI_LICENSE,
        "attribution": NUCLEI_ATTRIBUTION,
    }
    (out_dir / "_provenance_nuclei.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8",
    )
    print(
        f"converted={converted} skipped={skipped} errors={errors} "
        f"→ {out_dir}",
    )
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
