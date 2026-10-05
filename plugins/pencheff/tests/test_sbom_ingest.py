"""Tests for ``pencheff.modules.sca.sbom_ingest`` — SBOM parsers
(CycloneDX 1.4–1.6, SPDX 2.3, Syft JSON) and the diff helper.
"""
from __future__ import annotations

import json

import pytest

from pencheff.modules.sca.sbom_ingest import (
    compare_sboms,
    detect_sbom_format,
    ingest_sbom,
    parse_cyclonedx_json,
    parse_spdx_json,
    parse_syft_json,
)
from pencheff.modules.sca.manifest_parsers import Dep


# ── CycloneDX ────────────────────────────────────────────────────────


def test_cyclonedx_basic(tmp_path):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"type": "library", "name": "lodash", "version": "4.17.20",
             "purl": "pkg:npm/lodash@4.17.20",
             "licenses": [{"license": {"id": "MIT"}}]},
            {"type": "library", "name": "flask", "version": "2.0.0",
             "purl": "pkg:pypi/flask@2.0.0"},
        ],
    }
    p = tmp_path / "bom.cdx.json"
    p.write_text(json.dumps(sbom))
    deps = parse_cyclonedx_json(p)
    assert len(deps) == 2
    by_name = {d.name: d for d in deps}
    assert by_name["lodash"].ecosystem == "npm"
    assert by_name["lodash"].license == "MIT"
    assert by_name["flask"].ecosystem == "PyPI"
    assert by_name["flask"].version == "2.0.0"


def test_cyclonedx_maven_namespace(tmp_path):
    """Maven components use a namespaced PURL: pkg:maven/group/artifact@v"""
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "components": [
            {"type": "library", "name": "commons-lang3", "version": "3.10",
             "group": "org.apache.commons",
             "purl": "pkg:maven/org.apache.commons/commons-lang3@3.10"},
        ],
    }
    p = tmp_path / "bom.json"
    p.write_text(json.dumps(sbom))
    deps = parse_cyclonedx_json(p)
    assert len(deps) == 1
    assert deps[0].ecosystem == "Maven"
    # OSV expects "group:artifact" for Maven coords.
    assert deps[0].name == "org.apache.commons:commons-lang3"


def test_cyclonedx_skips_components_with_no_ecosystem(tmp_path):
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [
            {"type": "library", "name": "ghost", "version": "1.0"},
            {"type": "library", "name": "lodash", "version": "4.0",
             "purl": "pkg:npm/lodash@4.0"},
        ],
    }
    p = tmp_path / "bom.json"
    p.write_text(json.dumps(sbom))
    deps = parse_cyclonedx_json(p)
    assert len(deps) == 1 and deps[0].name == "lodash"


# ── SPDX ─────────────────────────────────────────────────────────────


def test_spdx_2_3_with_purl(tmp_path):
    sbom = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "packages": [
            {
                "name": "requests", "versionInfo": "2.30.0",
                "licenseConcluded": "Apache-2.0",
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType":     "purl",
                    "referenceLocator":  "pkg:pypi/requests@2.30.0",
                }],
            },
            {
                "name": "axios", "versionInfo": "1.0.0",
                "externalRefs": [{
                    "referenceType":    "purl",
                    "referenceLocator": "pkg:npm/axios@1.0.0",
                }],
            },
        ],
    }
    p = tmp_path / "bom.spdx.json"
    p.write_text(json.dumps(sbom))
    deps = parse_spdx_json(p)
    assert len(deps) == 2
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].ecosystem == "PyPI"
    assert by_name["requests"].license == "Apache-2.0"
    assert by_name["axios"].ecosystem == "npm"


def test_spdx_skips_packages_without_purl(tmp_path):
    """SPDX SBOMs sometimes list system packages without PURLs (the kernel,
    the OS itself). Skip those — OSV won't have advisory data for them."""
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {"name": "kernel", "versionInfo": "5.15"},  # no purl
            {"name": "lodash", "versionInfo": "4.0",
             "externalRefs": [{"referenceType": "purl",
                               "referenceLocator": "pkg:npm/lodash@4.0"}]},
        ],
    }
    p = tmp_path / "bom.spdx.json"
    p.write_text(json.dumps(sbom))
    deps = parse_spdx_json(p)
    assert len(deps) == 1 and deps[0].name == "lodash"


# ── Syft ─────────────────────────────────────────────────────────────


def test_syft_native_format(tmp_path):
    sbom = {
        "schema": {"version": "16.0.0",
                   "url": "https://anchore.io/schemas/syft/16.0.0.json"},
        "artifacts": [
            {"id": "x1", "name": "click", "version": "8.1.0",
             "type": "python",
             "purl": "pkg:pypi/click@8.1.0",
             "licenses": [{"value": "BSD-3-Clause"}]},
            {"id": "x2", "name": "express", "version": "4.18.0",
             "type": "npm",
             "purl": "pkg:npm/express@4.18.0"},
        ],
    }
    p = tmp_path / "syft.json"
    p.write_text(json.dumps(sbom))
    deps = parse_syft_json(p)
    assert len(deps) == 2
    by_name = {d.name: d for d in deps}
    assert by_name["click"].ecosystem == "PyPI"
    assert by_name["click"].license == "BSD-3-Clause"
    assert by_name["express"].ecosystem == "npm"


# ── Format detection ────────────────────────────────────────────────


def test_detect_cyclonedx(tmp_path):
    p = tmp_path / "bom.json"
    p.write_text(json.dumps({"bomFormat": "CycloneDX",
                             "specVersion": "1.5",
                             "components": []}))
    assert detect_sbom_format(p) == "cyclonedx"


def test_detect_spdx(tmp_path):
    p = tmp_path / "bom.json"
    p.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": []}))
    assert detect_sbom_format(p) == "spdx"


def test_detect_syft(tmp_path):
    p = tmp_path / "syft.json"
    p.write_text(json.dumps({
        "schema": {"url": "https://anchore.io/schemas/syft/16.0.0.json"},
        "artifacts": [],
    }))
    assert detect_sbom_format(p) == "syft"


def test_detect_returns_none_for_unknown(tmp_path):
    p = tmp_path / "random.json"
    p.write_text('{"hello": "world"}')
    assert detect_sbom_format(p) is None


def test_ingest_dispatches_correctly(tmp_path):
    p = tmp_path / "bom.json"
    p.write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [{"type": "library", "name": "lodash",
                        "purl": "pkg:npm/lodash@4.0",
                        "version": "4.0"}],
    }))
    deps = ingest_sbom(p)
    assert len(deps) == 1 and deps[0].ecosystem == "npm"


# ── Diff ────────────────────────────────────────────────────────────


def test_compare_sboms_added_removed_upgraded():
    base = [
        Dep(name="a", version="1.0.0", ecosystem="npm"),
        Dep(name="b", version="2.0.0", ecosystem="npm"),
        Dep(name="c", version="3.0.0", ecosystem="npm"),
    ]
    head = [
        Dep(name="a", version="1.0.0", ecosystem="npm"),  # unchanged
        Dep(name="b", version="2.5.0", ecosystem="npm"),  # upgraded
        Dep(name="d", version="1.0.0", ecosystem="npm"),  # added
    ]
    diff = compare_sboms(base, head)
    assert {x["name"] for x in diff["added"]} == {"d"}
    assert {x["name"] for x in diff["removed"]} == {"c"}
    assert len(diff["upgraded"]) == 1
    assert diff["upgraded"][0]["name"] == "b"
    assert diff["upgraded"][0]["from"] == "2.0.0"
    assert diff["upgraded"][0]["to"] == "2.5.0"
    assert diff["downgraded"] == []


def test_compare_sboms_downgrade_detected():
    base = [Dep(name="x", version="2.0.0", ecosystem="npm")]
    head = [Dep(name="x", version="1.5.0", ecosystem="npm")]
    diff = compare_sboms(base, head)
    assert len(diff["downgraded"]) == 1
    assert diff["upgraded"] == []
    assert diff["added"] == [] and diff["removed"] == []


def test_compare_distinguishes_ecosystem():
    """Same package name across two ecosystems must be tracked separately."""
    base = [Dep(name="lodash", version="1.0", ecosystem="npm")]
    head = [Dep(name="lodash", version="1.0", ecosystem="PyPI")]
    diff = compare_sboms(base, head)
    assert len(diff["added"]) == 1
    assert len(diff["removed"]) == 1


# ── Discover-and-parse integration ──────────────────────────────────


def test_discover_picks_up_sbom(tmp_path):
    """A CycloneDX SBOM dropped into the tree should flow through
    ``discover_and_parse`` exactly like a manifest would."""
    from pencheff.modules.sca.manifest_parsers import discover_and_parse

    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "18.0.0"}}'
    )
    (tmp_path / "bom.cdx.json").write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [
            {"type": "library", "name": "axios", "version": "1.0.0",
             "purl": "pkg:npm/axios@1.0.0"},
        ],
    }))
    deps = discover_and_parse(tmp_path)
    names = {d.name for d in deps}
    assert "react" in names      # from package.json
    assert "axios" in names      # from the SBOM
