"""Generate SPDX 2.3 and CycloneDX 1.5 SBOMs from discovered dependencies.

If ``syft`` is available on PATH, shell out to it for better fidelity; otherwise
use the native manifest parsers (accepting reduced completeness).
"""

from __future__ import annotations

import hashlib
import json
import subprocess  # noqa: S404 — safe: only runs allowlisted tools
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pencheff.modules.sca.manifest_parsers import Dep, discover_and_parse


def generate_sbom(
    root: Path,
    fmt: str = "cyclonedx",
    prefer_syft: bool = True,
) -> dict[str, Any]:
    """Return a dict containing the SBOM and metadata.

    ``fmt`` is one of: ``cyclonedx``, ``spdx``, ``both``.
    """
    deps = discover_and_parse(root)
    result: dict[str, Any] = {
        "component_count": len(deps),
        "formats": {},
        "source": "native-parsers",
    }
    if prefer_syft and _syft_available():
        try:
            cdx = _run_syft(root, "cyclonedx-json")
            if cdx:
                result["formats"]["cyclonedx"] = json.loads(cdx)
                result["source"] = "syft"
        except Exception:  # noqa: BLE001
            pass
        try:
            spdx = _run_syft(root, "spdx-json")
            if spdx:
                result["formats"]["spdx"] = json.loads(spdx)
        except Exception:  # noqa: BLE001
            pass

    if "cyclonedx" not in result["formats"] and fmt in ("cyclonedx", "both"):
        result["formats"]["cyclonedx"] = _build_cyclonedx(deps, root)
    if "spdx" not in result["formats"] and fmt in ("spdx", "both"):
        result["formats"]["spdx"] = _build_spdx(deps, root)
    return result


def _syft_available() -> bool:
    try:
        subprocess.run(
            ["syft", "--version"], capture_output=True, timeout=5, check=False
        )
        return True
    except (FileNotFoundError, subprocess.SubprocessError):
        return False


def _run_syft(root: Path, fmt: str) -> str:
    p = subprocess.run(
        ["syft", str(root), "-o", fmt],
        capture_output=True, text=True, timeout=120, check=False,
    )
    if p.returncode != 0:
        return ""
    return p.stdout


def _build_cyclonedx(deps: list[Dep], root: Path) -> dict[str, Any]:
    serial = "urn:uuid:" + str(uuid.uuid4())
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "pencheff", "name": "pencheff-sbom", "version": "1.0"}],
            "component": {
                "type": "application",
                "name": root.name or "project",
                "bom-ref": f"pkg:app/{root.name}",
            },
        },
        "components": [
            {
                "type": "library",
                "bom-ref": _purl(d),
                "name": d.name,
                "version": d.version,
                "purl": _purl(d),
                "licenses": ([{"license": {"id": d.license}}] if d.license else []),
                "properties": [
                    {"name": "pencheff:ecosystem", "value": d.ecosystem},
                    {"name": "pencheff:scope", "value": d.scope},
                    {"name": "pencheff:source_file", "value": d.source_file},
                ],
            }
            for d in deps
        ],
    }


def _build_spdx(deps: list[Dep], root: Path) -> dict[str, Any]:
    doc_id = "SPDXRef-DOCUMENT"
    root_id = f"SPDXRef-App-{_sha1(root.name)[:10]}"
    now = datetime.now(timezone.utc).isoformat()
    packages = [{
        "SPDXID": root_id,
        "name": root.name or "project",
        "versionInfo": "",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
    }]
    relationships = [{
        "spdxElementId": doc_id,
        "relatedSpdxElement": root_id,
        "relationshipType": "DESCRIBES",
    }]
    for d in deps:
        sid = f"SPDXRef-Pkg-{_sha1(_purl(d))[:14]}"
        packages.append({
            "SPDXID": sid,
            "name": d.name,
            "versionInfo": d.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseDeclared": d.license or "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": _purl(d),
            }],
        })
        relationships.append({
            "spdxElementId": root_id,
            "relatedSpdxElement": sid,
            "relationshipType": "DEPENDS_ON",
        })
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_id,
        "name": f"{root.name}-sbom",
        "documentNamespace": f"https://pencheff.dev/sbom/{uuid.uuid4()}",
        "creationInfo": {
            "created": now,
            "creators": ["Tool: pencheff-sbom-1.0"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def _purl(d: Dep) -> str:
    eco = {
        "npm": "npm", "PyPI": "pypi", "Go": "golang",
        "crates.io": "cargo", "RubyGems": "gem",
        "Packagist": "composer", "Maven": "maven",
    }.get(d.ecosystem, d.ecosystem.lower())
    return f"pkg:{eco}/{d.name}@{d.version}" if d.version else f"pkg:{eco}/{d.name}"


def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode(), usedforsecurity=False).hexdigest()
