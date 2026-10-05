#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate the Pencheff project's own SBOMs (CycloneDX 1.5 + SPDX 2.3).

This is the supply-chain-attestation side of Phase 1.3 — the SaaS
worker generates SBOMs *for customer repos* via the same engine, but
this wrapper points the engine at Pencheff itself so each release
ships an SBOM auditors can ingest.

Outputs (in ``--output-dir``, default ``./sbom-out``):

    cyclonedx.json   — CycloneDX 1.5
    spdx.json        — SPDX 2.3

The release workflow at ``.github/workflows/release-sbom.yml`` invokes
this script on every ``v*.*.*`` tag, then signs the outputs with
cosign and attaches them as release assets. The same files re-render
on the repo's web UI ``/repos/{id}/sbom`` view when Pencheff scans
itself, so the customer-facing rollup stays consistent.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Repo root is two levels up from this file (``tools/`` lives at root).
REPO_ROOT = Path(__file__).resolve().parents[1]


def _ensure_plugin_importable() -> None:
    """Make the Pencheff plugin package importable in the CI image.

    The release workflow installs the plugin via ``pip install -e
    plugins/pencheff`` before invoking us, so this is a belt-and-braces
    fallback for local dev runs.
    """
    plugin_root = REPO_ROOT / "plugins" / "pencheff"
    if not plugin_root.is_dir():
        return
    if str(plugin_root) not in sys.path:
        sys.path.insert(0, str(plugin_root))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate Pencheff's own CycloneDX + SPDX SBOMs.",
    )
    parser.add_argument(
        "--output-dir", default=str(REPO_ROOT / "sbom-out"),
        help="Directory to write cyclonedx.json + spdx.json into.",
    )
    parser.add_argument(
        "--root", default=str(REPO_ROOT),
        help="Path to scan (default: repo root).",
    )
    args = parser.parse_args()

    _ensure_plugin_importable()
    try:
        from pencheff.modules.sca.sbom_generator import generate_sbom
    except ImportError as exc:
        print(
            f"error: cannot import pencheff.modules.sca.sbom_generator: {exc}\n"
            "Install the plugin first: pip install -e plugins/pencheff",
            file=sys.stderr,
        )
        return 1

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    result = generate_sbom(Path(args.root).resolve(), fmt="both")

    cdx = result["formats"].get("cyclonedx")
    spdx = result["formats"].get("spdx")

    if cdx is not None:
        cdx_path = out_dir / "cyclonedx.json"
        cdx_path.write_text(json.dumps(cdx, indent=2, sort_keys=True), encoding="utf-8")
        print(f"wrote {cdx_path}")
    if spdx is not None:
        spdx_path = out_dir / "spdx.json"
        spdx_path.write_text(json.dumps(spdx, indent=2, sort_keys=True), encoding="utf-8")
        print(f"wrote {spdx_path}")

    print(
        f"source: {result.get('source')}, "
        f"components: {result.get('component_count', 0)}",
    )
    return 0 if (cdx or spdx) else 1


if __name__ == "__main__":
    sys.exit(main())
