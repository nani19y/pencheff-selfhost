"""Ingest SBOMs produced by external tools and convert to Pencheff's
``Dep`` type so the existing OSV/EPSS/KEV pipeline can scan them.

Formats supported:

  * **CycloneDX 1.4 / 1.5 / 1.6** (JSON)  — produced by Trivy, Grype,
    cdxgen, syft (``--format cyclonedx-json``), Maven cyclonedx-plugin.
  * **SPDX 2.2 / 2.3** (JSON)             — produced by syft, FOSSA, GitHub.
    Tag-value SPDX (``.spdx`` files) is intentionally not supported in
    v1; users in the wild produce JSON-SPDX 99% of the time.
  * **Syft JSON** (native)                — produced by ``syft --format=json``.

Format detection is content-based (we sniff for ``bomFormat``,
``spdxVersion``, ``schema.url`` containing "syft") so a file extension of
``.json`` is enough — no need for users to label their SBOM.

The diff helper (``compare_sboms``) takes two SBOMs and returns the
ecosystem-aware add/remove/upgrade/downgrade lists. Useful for the
"what changed since last release" view on the dashboard.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from pencheff.modules.sca.manifest_parsers import Dep


# ── PURL → ecosystem ────────────────────────────────────────────────


_PURL_TO_ECOSYSTEM: dict[str, str] = {
    "npm":      "npm",
    "pypi":     "PyPI",
    "gem":      "RubyGems",
    "cargo":    "crates.io",
    "golang":   "Go",
    "maven":    "Maven",
    "composer": "Packagist",
    "nuget":    "NuGet",
    "pub":      "Pub",
    "swift":    "Swift",
    "hex":      "Hex",
    "cran":     "CRAN",
    "deb":      "Debian",
    "rpm":      "RedHat",
    "apk":      "Alpine",
    "conan":    "ConanCenter",
}


_PURL_RX = re.compile(
    r"^pkg:(?P<type>[^/@?#]+)"
    r"(?:/(?P<namespace>[^/@?#]+))?"
    r"/(?P<name>[^@?#]+)"
    r"@(?P<version>[^?#]+)"
)


def _ecosystem_from_purl(purl: str) -> str:
    """Map a Package URL to a Pencheff ecosystem label. Returns ``""`` if
    the PURL is malformed or the type is unknown — caller should fall
    back to the SBOM's own type field if available."""
    if not purl:
        return ""
    m = _PURL_RX.match(purl)
    if not m:
        return ""
    return _PURL_TO_ECOSYSTEM.get(m.group("type").lower(), "")


def _parse_purl_name(purl: str) -> tuple[str, str]:
    """Pull (name, version) from a PURL, normalising the namespace where
    OSV expects "namespace:name" (Maven) vs "name" (npm/pypi)."""
    if not purl:
        return "", ""
    m = _PURL_RX.match(purl)
    if not m:
        return "", ""
    name = m.group("name")
    namespace = m.group("namespace") or ""
    type_ = m.group("type").lower()
    if type_ == "maven" and namespace:
        name = f"{namespace}:{name}"
    elif namespace:
        name = f"{namespace}/{name}"
    return name, m.group("version")


# ── Format detection ────────────────────────────────────────────────


def detect_sbom_format(path: Path) -> str | None:
    """Return one of ``'cyclonedx'``, ``'spdx'``, ``'syft'``, or ``None``."""
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    head = text.lstrip()[:2048]
    try:
        data = json.loads(head + (text[len(head):] if not head.endswith("}") else ""))
    except json.JSONDecodeError:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
    if isinstance(data, dict):
        if data.get("bomFormat") == "CycloneDX":
            return "cyclonedx"
        if isinstance(data.get("spdxVersion"), str) and data["spdxVersion"].startswith("SPDX"):
            return "spdx"
        schema = data.get("schema") or {}
        if isinstance(schema, dict) and "syft" in str(schema.get("url", "")).lower():
            return "syft"
        # Some Syft outputs put the schema inline — also check `artifacts`
        # against the syft shape (always has `type` per artifact).
        artifacts = data.get("artifacts")
        if isinstance(artifacts, list) and artifacts and isinstance(artifacts[0], dict):
            if "type" in artifacts[0] and "name" in artifacts[0]:
                return "syft"
    return None


# ── Format parsers ──────────────────────────────────────────────────


def parse_cyclonedx_json(path: Path) -> list[Dep]:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    out: list[Dep] = []
    for comp in data.get("components") or []:
        purl = comp.get("purl") or ""
        ecosystem = _ecosystem_from_purl(purl)
        name = comp.get("name", "")
        version = comp.get("version", "")
        # Maven group:artifact lives in `group` outside the PURL.
        if not ecosystem and comp.get("group"):
            name = f"{comp['group']}:{name}"
            ecosystem = "Maven"
        if purl:
            purl_name, purl_ver = _parse_purl_name(purl)
            if purl_name:
                name = purl_name
            if purl_ver:
                version = purl_ver
        if not name or not ecosystem:
            continue
        license_obj = comp.get("licenses") or []
        license_id: str | None = None
        if license_obj:
            first = license_obj[0]
            if isinstance(first, dict):
                lic = first.get("license") or {}
                if isinstance(lic, dict):
                    license_id = lic.get("id") or lic.get("name")
                else:
                    license_id = first.get("expression")
        out.append(Dep(
            name=name, version=version, ecosystem=ecosystem,
            scope="runtime", license=license_id, source_file=str(path),
        ))
    return out


def parse_spdx_json(path: Path) -> list[Dep]:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    out: list[Dep] = []
    for pkg in data.get("packages") or []:
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "") or ""
        ecosystem = ""
        # PURLs live in externalRefs[*].referenceLocator when
        # referenceType == "purl".
        for ref in pkg.get("externalRefs") or []:
            if (ref.get("referenceType") or "").lower() == "purl":
                purl = ref.get("referenceLocator") or ""
                ecosystem = _ecosystem_from_purl(purl)
                purl_name, purl_ver = _parse_purl_name(purl)
                if purl_name:
                    name = purl_name
                if purl_ver:
                    version = purl_ver
                if ecosystem:
                    break
        if not name or not ecosystem:
            continue
        out.append(Dep(
            name=name, version=version, ecosystem=ecosystem,
            scope="runtime",
            license=pkg.get("licenseConcluded") or pkg.get("licenseDeclared"),
            source_file=str(path),
        ))
    return out


_SYFT_TYPE_TO_ECOSYSTEM: dict[str, str] = {
    "python":    "PyPI",
    "npm":       "npm",
    "gem":       "RubyGems",
    "cargo":     "crates.io",
    "go-module": "Go",
    "java":      "Maven",
    "maven":     "Maven",
    "composer":  "Packagist",
    "nuget":     "NuGet",
    "deb":       "Debian",
    "rpm":       "RedHat",
    "apk":       "Alpine",
    "conan":     "ConanCenter",
}


def parse_syft_json(path: Path) -> list[Dep]:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    out: list[Dep] = []
    for art in data.get("artifacts") or []:
        name = art.get("name", "")
        version = art.get("version", "") or ""
        type_ = (art.get("type") or "").lower()
        ecosystem = _SYFT_TYPE_TO_ECOSYSTEM.get(type_, "")
        # Prefer PURL-derived ecosystem when present (handles namespaced
        # Java / Maven artifacts that Syft labels as plain "java").
        purl = art.get("purl") or ""
        purl_eco = _ecosystem_from_purl(purl)
        if purl_eco:
            ecosystem = purl_eco
            purl_name, purl_ver = _parse_purl_name(purl)
            if purl_name:
                name = purl_name
            if purl_ver:
                version = purl_ver
        if not name or not ecosystem:
            continue
        license_id: str | None = None
        licenses = art.get("licenses") or []
        if licenses and isinstance(licenses[0], dict):
            license_id = licenses[0].get("value") or licenses[0].get("name")
        elif licenses and isinstance(licenses[0], str):
            license_id = licenses[0]
        out.append(Dep(
            name=name, version=version, ecosystem=ecosystem,
            scope="runtime", license=license_id, source_file=str(path),
        ))
    return out


def ingest_sbom(path: Path) -> list[Dep]:
    """Detect format and parse. Returns ``[]`` for unknown / malformed."""
    fmt = detect_sbom_format(path)
    if fmt == "cyclonedx":
        return parse_cyclonedx_json(path)
    if fmt == "spdx":
        return parse_spdx_json(path)
    if fmt == "syft":
        return parse_syft_json(path)
    return []


# ── Diff ────────────────────────────────────────────────────────────


def compare_sboms(
    base: Iterable[Dep], head: Iterable[Dep],
) -> dict[str, list[dict[str, str]]]:
    """Return ``{added, removed, upgraded, downgraded}`` between two SBOMs.

    Comparison is keyed on ``(ecosystem, name)`` — version drift is the
    interesting axis. The output is JSON-friendly so the dashboard can
    render it directly.
    """
    base_map = {(d.ecosystem, d.name): d for d in base}
    head_map = {(d.ecosystem, d.name): d for d in head}
    added, removed, upgraded, downgraded = [], [], [], []
    for key, head_d in head_map.items():
        base_d = base_map.get(key)
        if base_d is None:
            added.append({
                "ecosystem": head_d.ecosystem, "name": head_d.name,
                "version": head_d.version,
            })
            continue
        if base_d.version == head_d.version:
            continue
        cmp = _version_cmp(base_d.version, head_d.version)
        record = {
            "ecosystem": head_d.ecosystem, "name": head_d.name,
            "from": base_d.version, "to": head_d.version,
        }
        if cmp < 0:
            upgraded.append(record)
        elif cmp > 0:
            downgraded.append(record)
    for key, base_d in base_map.items():
        if key not in head_map:
            removed.append({
                "ecosystem": base_d.ecosystem, "name": base_d.name,
                "version": base_d.version,
            })
    return {
        "added":      added,
        "removed":    removed,
        "upgraded":   upgraded,
        "downgraded": downgraded,
    }


_VERSION_PART_RX = re.compile(r"(\d+)|([A-Za-z]+)")


def _version_cmp(a: str, b: str) -> int:
    """Return -1 / 0 / 1 — best-effort SemVer/PEP-440 comparison.

    Cross-ecosystem version comparison is genuinely hard (npm SemVer,
    Python PEP-440, Maven, Go module versions all diverge). We do a
    component-wise compare that handles the ~95% case (numeric components
    compare as numbers, alpha components compare lexicographically). A
    full per-ecosystem implementation lives in dedicated parsers and is
    out of scope for the SBOM diff use case.
    """
    if a == b:
        return 0
    pa = [(int(n) if n else None, alpha) for n, alpha in _VERSION_PART_RX.findall(a)]
    pb = [(int(n) if n else None, alpha) for n, alpha in _VERSION_PART_RX.findall(b)]
    for (na, aa), (nb, ab) in zip(pa, pb):
        if na is not None and nb is not None:
            if na != nb:
                return -1 if na < nb else 1
        elif na is not None and nb is None:
            return 1
        elif nb is not None and na is None:
            return -1
        else:
            if aa != ab:
                return -1 if aa < ab else 1
    if len(pa) != len(pb):
        return -1 if len(pa) < len(pb) else 1
    return 0
