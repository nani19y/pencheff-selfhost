"""Native parsers for common dependency manifest files.

Each parser returns a list of ``Dep`` records. All parsers tolerate malformed
input gracefully (return ``[]``) so a best-effort scan succeeds even when a
single lockfile is broken.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Dep:
    name: str
    version: str
    ecosystem: str  # npm, PyPI, Go, crates.io, Maven, RubyGems, Packagist
    scope: str = "runtime"  # runtime | dev | peer | optional
    license: str | None = None
    source_file: str = ""
    extras: dict[str, str] = field(default_factory=dict)


# ─── Node.js ──────────────────────────────────────────────────────────

def parse_package_lock(path: Path) -> list[Dep]:
    try:
        data = json.loads(path.read_text())
    except Exception:  # noqa: BLE001
        return []
    out: list[Dep] = []
    # npm v7+ "packages" form
    for key, meta in (data.get("packages") or {}).items():
        if not key or key == "":
            continue
        name = meta.get("name") or key.split("node_modules/")[-1]
        version = meta.get("version", "")
        scope = "dev" if meta.get("dev") else "runtime"
        out.append(Dep(
            name=name,
            version=version,
            ecosystem="npm",
            scope=scope,
            license=meta.get("license"),
            source_file=str(path),
        ))
    # Fall back to v6 "dependencies"
    if not out:
        for name, meta in (data.get("dependencies") or {}).items():
            out.append(Dep(
                name=name, version=meta.get("version", ""),
                ecosystem="npm", source_file=str(path),
            ))
    return out


def parse_package_json(path: Path) -> list[Dep]:
    try:
        data = json.loads(path.read_text())
    except Exception:  # noqa: BLE001
        return []
    out: list[Dep] = []
    for scope_key, scope_name in (
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("peerDependencies", "peer"),
        ("optionalDependencies", "optional"),
    ):
        for name, ver in (data.get(scope_key) or {}).items():
            out.append(Dep(
                name=name, version=str(ver).lstrip("^~>=<"),
                ecosystem="npm", scope=scope_name, source_file=str(path),
            ))
    return out


# ─── Python ───────────────────────────────────────────────────────────

def parse_requirements_txt(path: Path) -> list[Dep]:
    out: list[Dep] = []
    try:
        for line in path.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*([<>=!~]{1,2})\s*([A-Za-z0-9.\-+*]+)", line)
            if not m:
                m2 = re.match(r"^([A-Za-z0-9_.\-]+)$", line)
                if m2:
                    out.append(Dep(name=m2.group(1), version="",
                                   ecosystem="PyPI", source_file=str(path)))
                continue
            out.append(Dep(
                name=m.group(1).split("[")[0],
                version=m.group(3),
                ecosystem="PyPI",
                source_file=str(path),
            ))
    except Exception:  # noqa: BLE001
        return []
    return out


def parse_pyproject(path: Path) -> list[Dep]:
    try:
        data = tomllib.loads(path.read_text())
    except Exception:  # noqa: BLE001
        return []
    out: list[Dep] = []
    project = data.get("project", {})
    for item in project.get("dependencies", []) or []:
        d = _parse_pep508(item, path)
        if d:
            out.append(d)
    for _group, items in (project.get("optional-dependencies", {}) or {}).items():
        for item in items:
            d = _parse_pep508(item, path)
            if d:
                d.scope = "optional"
                out.append(d)
    # Poetry
    poetry = data.get("tool", {}).get("poetry", {})
    for name, spec in (poetry.get("dependencies") or {}).items():
        if name == "python":
            continue
        version = spec if isinstance(spec, str) else spec.get("version", "")
        out.append(Dep(
            name=name, version=str(version).lstrip("^~>=<"),
            ecosystem="PyPI", source_file=str(path),
        ))
    return out


def _parse_pep508(s: str, path: Path) -> Dep | None:
    s = s.split(";", 1)[0].strip()
    m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*([<>=!~]{1,2})\s*([A-Za-z0-9.\-+*]+)", s)
    if m:
        return Dep(
            name=m.group(1).split("[")[0],
            version=m.group(3),
            ecosystem="PyPI",
            source_file=str(path),
        )
    m2 = re.match(r"^([A-Za-z0-9_.\-]+)$", s)
    if m2:
        return Dep(name=m2.group(1), version="",
                   ecosystem="PyPI", source_file=str(path))
    return None


def parse_poetry_lock(path: Path) -> list[Dep]:
    try:
        data = tomllib.loads(path.read_text())
    except Exception:  # noqa: BLE001
        return []
    out: list[Dep] = []
    for pkg in data.get("package", []) or []:
        out.append(Dep(
            name=pkg.get("name", ""),
            version=pkg.get("version", ""),
            ecosystem="PyPI",
            scope=pkg.get("category", "runtime"),
            source_file=str(path),
        ))
    return out


# ─── Go ───────────────────────────────────────────────────────────────

def parse_go_mod(path: Path) -> list[Dep]:
    out: list[Dep] = []
    try:
        in_block = False
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if line.startswith("require ("):
                in_block = True
                continue
            if in_block and line == ")":
                in_block = False
                continue
            if in_block:
                parts = line.split()
                if len(parts) >= 2:
                    out.append(Dep(name=parts[0], version=parts[1],
                                   ecosystem="Go", source_file=str(path)))
            elif line.startswith("require "):
                parts = line.replace("require", "", 1).strip().split()
                if len(parts) >= 2:
                    out.append(Dep(name=parts[0], version=parts[1],
                                   ecosystem="Go", source_file=str(path)))
    except Exception:  # noqa: BLE001
        return []
    return out


# ─── Rust ─────────────────────────────────────────────────────────────

def parse_cargo_lock(path: Path) -> list[Dep]:
    try:
        data = tomllib.loads(path.read_text())
    except Exception:  # noqa: BLE001
        return []
    out: list[Dep] = []
    for pkg in data.get("package", []) or []:
        out.append(Dep(
            name=pkg.get("name", ""),
            version=pkg.get("version", ""),
            ecosystem="crates.io",
            source_file=str(path),
        ))
    return out


# ─── Ruby / Bundler ───────────────────────────────────────────────────

def parse_gemfile_lock(path: Path) -> list[Dep]:
    out: list[Dep] = []
    try:
        in_specs = False
        for raw in path.read_text().splitlines():
            line = raw.rstrip()
            if line.strip() == "GEM":
                continue
            if line.strip() == "specs:":
                in_specs = True
                continue
            if line.strip() == "" and in_specs:
                in_specs = False
                continue
            if in_specs and line.startswith("    "):
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1].startswith("("):
                    out.append(Dep(
                        name=parts[0],
                        version=parts[1].strip("()"),
                        ecosystem="RubyGems",
                        source_file=str(path),
                    ))
    except Exception:  # noqa: BLE001
        return []
    return out


# ─── PHP / Composer ───────────────────────────────────────────────────

def parse_composer_lock(path: Path) -> list[Dep]:
    try:
        data = json.loads(path.read_text())
    except Exception:  # noqa: BLE001
        return []
    out: list[Dep] = []
    for key in ("packages", "packages-dev"):
        for pkg in data.get(key, []) or []:
            out.append(Dep(
                name=pkg.get("name", ""),
                version=pkg.get("version", ""),
                ecosystem="Packagist",
                scope="dev" if key == "packages-dev" else "runtime",
                license=(pkg.get("license") or [None])[0],
                source_file=str(path),
            ))
    return out


# ─── Java / Maven ─────────────────────────────────────────────────────

def parse_pom_xml(path: Path) -> list[Dep]:
    """Best-effort XML parse; users should prefer dependency-check CLI."""
    out: list[Dep] = []
    try:
        text = path.read_text()
        for match in re.finditer(
            r"<dependency>(.*?)</dependency>", text, flags=re.DOTALL
        ):
            block = match.group(1)
            gid = re.search(r"<groupId>([^<]+)</groupId>", block)
            aid = re.search(r"<artifactId>([^<]+)</artifactId>", block)
            ver = re.search(r"<version>([^<]+)</version>", block)
            if gid and aid:
                out.append(Dep(
                    name=f"{gid.group(1)}:{aid.group(1)}",
                    version=ver.group(1) if ver else "",
                    ecosystem="Maven",
                    source_file=str(path),
                ))
    except Exception:  # noqa: BLE001
        return []
    return out


# ─── Dispatch ─────────────────────────────────────────────────────────

PARSERS: dict[str, callable] = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "package.json": parse_package_json,
    "requirements.txt": parse_requirements_txt,
    "requirements-dev.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject,
    "poetry.lock": parse_poetry_lock,
    "go.mod": parse_go_mod,
    "Cargo.lock": parse_cargo_lock,
    "Gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
    "pom.xml": parse_pom_xml,
}


def discover_and_parse(root: Path) -> list[Dep]:
    """Walk ``root`` and parse every supported manifest file found.

    Also ingests any SPDX / CycloneDX / Syft JSON SBOM that happens to be
    in the tree — useful when a CI job has already produced an SBOM and
    committed it next to the manifests.
    """
    # Lazy import to avoid a cycle at module load time.
    from pencheff.modules.sca.sbom_ingest import detect_sbom_format, ingest_sbom

    out: list[Dep] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.name in PARSERS:
            try:
                out.extend(PARSERS[p.name](p))
            except Exception:  # noqa: BLE001
                continue
            continue
        # Heuristic SBOM probe — only on .json / .cdx.json / .spdx.json
        # to avoid sniffing every text file in the tree.
        n = p.name.lower()
        if n.endswith((".json", ".cdx.json", ".spdx.json", ".syft.json")):
            try:
                if detect_sbom_format(p) is not None:
                    out.extend(ingest_sbom(p))
            except Exception:  # noqa: BLE001
                continue
    # dedupe by (ecosystem, name, version)
    seen: set[tuple[str, str, str]] = set()
    unique: list[Dep] = []
    for d in out:
        key = (d.ecosystem, d.name, d.version)
        if key in seen:
            continue
        seen.add(key)
        unique.append(d)
    return unique
