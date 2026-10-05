#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""License audit + NOTICES generator.

Two modes:

* ``audit`` (default) — walk the repo's dependency manifests, look up
  each dependency's license, and fail when the license is not on the
  allowlist (``tools/license-allowlist.txt``).

* ``--write-notices`` — regenerate ``THIRD_PARTY_NOTICES.md`` (root)
  deterministically from the same dependency walk. CI checks the
  committed file matches what the generator produces.

Designed to run on every PR via ``.github/workflows/license-audit.yml``.

The script intentionally avoids depending on ``pip-licenses`` /
``license-checker`` so it works in a minimal CI environment. It reads
manifests directly:

* Python: ``pyproject.toml`` files (PEP 621)
* Node: ``package.json`` files in ``apps/web``, ``apps/docs``,
  ``apps/extension``, ``apps/vscode``, ``apps/jetbrains``

Each manifest is converted into ``(name, version_spec, declared_license)``
rows. License lookups are best-effort — when the manifest doesn't
declare one, the row is logged as ``unknown`` and the audit fails
unless a per-package override exists in
``tools/license-overrides.txt``.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_PATH = REPO_ROOT / "tools" / "license-allowlist.txt"
OVERRIDES_PATH = REPO_ROOT / "tools" / "license-overrides.txt"
NOTICES_PATH = REPO_ROOT / "THIRD_PARTY_NOTICES.md"


@dataclass
class Dependency:
    name: str
    version: str
    license_id: str | None
    source_manifest: str
    ecosystem: str
    notes: list[str] = field(default_factory=list)


def _read_allowlist() -> set[str]:
    if not ALLOWLIST_PATH.is_file():
        return set()
    out: set[str] = set()
    for line in ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines():
        s = line.split("#", 1)[0].strip()
        if s:
            out.add(s)
    return out


def _read_overrides() -> dict[str, str]:
    """Per-package license overrides for cases where the manifest is wrong.

    Format: ``ecosystem:package = SPDX-License-Identifier`` per line.
    """
    if not OVERRIDES_PATH.is_file():
        return {}
    out: dict[str, str] = {}
    for line in OVERRIDES_PATH.read_text(encoding="utf-8").splitlines():
        s = line.split("#", 1)[0].strip()
        if not s or "=" not in s:
            continue
        key, value = s.split("=", 1)
        out[key.strip().lower()] = value.strip()
    return out


def _normalize_license(value: str | None) -> str | None:
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None
    # Common aliases that Python / Node ecosystems emit.
    aliases = {
        "MIT License": "MIT",
        "MIT license": "MIT",
        "BSD-3-Clause License": "BSD-3-Clause",
        "BSD-2-Clause License": "BSD-2-Clause",
        "Apache License 2.0": "Apache-2.0",
        "Apache-2": "Apache-2.0",
        "Apache 2.0": "Apache-2.0",
        "Apache License, Version 2.0": "Apache-2.0",
        "ISC License": "ISC",
        "Python Software Foundation License": "PSF-2.0",
        "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
        "Public-Domain": "Public Domain",
    }
    return aliases.get(s, s)


# ─── Python — pyproject.toml walk ─────────────────────────────────


_PEP503 = re.compile(r"[-_.]+")


def _python_dependencies() -> list[Dependency]:
    rows: list[Dependency] = []
    for pyproj in REPO_ROOT.rglob("pyproject.toml"):
        rel = str(pyproj.relative_to(REPO_ROOT))
        if any(skip in rel for skip in (".venv", "node_modules", "build", "dist")):
            continue
        try:
            data = tomllib.loads(pyproj.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        project = data.get("project") or {}
        deps = list(project.get("dependencies") or [])
        # PEP 621 optional-dependencies → flatten extras.
        for extras in (project.get("optional-dependencies") or {}).values():
            deps.extend(extras)
        for dep in deps:
            name = re.split(r"[<>=!~;\[]", dep, maxsplit=1)[0].strip()
            if not name:
                continue
            version_spec = dep[len(name):].strip() or "*"
            rows.append(Dependency(
                name=_PEP503.sub("-", name).lower(),
                version=version_spec,
                license_id=None,  # PEP 621 doesn't surface dep licenses here
                source_manifest=rel,
                ecosystem="pypi",
            ))
    return rows


# ─── Node — package.json walk ──────────────────────────────────────


_NODE_DIRS = (
    "apps/web", "apps/docs", "apps/extension",
    "apps/vscode", "apps/jetbrains",
)


def _node_dependencies() -> list[Dependency]:
    rows: list[Dependency] = []
    for sub in _NODE_DIRS:
        pkg = REPO_ROOT / sub / "package.json"
        if not pkg.is_file():
            continue
        rel = str(pkg.relative_to(REPO_ROOT))
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, version in (data.get(section) or {}).items():
                rows.append(Dependency(
                    name=name.lower(),
                    version=str(version),
                    license_id=None,
                    source_manifest=rel,
                    ecosystem="npm",
                    notes=[section],
                ))
    return rows


# ─── License hydration via overrides ───────────────────────────────


def _hydrate_licenses(deps: list[Dependency], overrides: dict[str, str]) -> None:
    for d in deps:
        key = f"{d.ecosystem}:{d.name}".lower()
        if key in overrides:
            d.license_id = overrides[key]
            d.notes.append("override")


# ─── Audit + reporting ─────────────────────────────────────────────


def _audit(deps: list[Dependency], allow: set[str]) -> tuple[list[Dependency], list[Dependency]]:
    ok: list[Dependency] = []
    bad: list[Dependency] = []
    norm_allow = {a.lower() for a in allow}
    for d in deps:
        lic = _normalize_license(d.license_id)
        if lic and lic.lower() in norm_allow:
            ok.append(d)
            continue
        bad.append(d)
    return ok, bad


def _print_audit(ok: list[Dependency], bad: list[Dependency]) -> None:
    print(f"License audit: {len(ok)} ok, {len(bad)} flagged.")
    if bad:
        print("\nFlagged dependencies (need an entry in tools/license-overrides.txt or allowlist):")
        for d in bad:
            label = d.license_id or "unknown"
            print(f"  - {d.ecosystem}:{d.name}  ({label})  ← {d.source_manifest}")


# ─── Static blocks ──────────────────────────────────────────────────
#
# Content that does NOT come from a manifest (subprocess tools, vuln
# feeds, optional toolchain image) lives in code so the generated file
# is fully reproducible from this script + the overrides file + the
# project's own pyproject.toml/package.json files. When you add a new
# subprocess tool or feed, edit these constants — never the generated
# markdown.

_SUBPROCESS_TOOLS_BLOCK = """\
## Subprocess-invoked external tools

The tools below are invoked as subprocesses by the SAST / DAST / SCA
scan paths. Their source code is not bundled or statically linked; they
are present only when installed in the deployment environment (the
optional toolchain Docker image, a system package manager, or the
runner's PATH).

| Component | License | Use | Source | Redistribution posture |
| --- | --- | --- | --- | --- |
| Semgrep CLI | LGPL-2.1 | SAST runner | https://semgrep.dev | Subprocess-only invocation. Pinned to an explicit allowlist of OSS Registry packs (`p/owasp-top-ten`, `p/security-audit`, `p/cwe-top-25`, `p/secrets`, `p/jwt`, `p/django`, `p/flask`, `p/express`, `p/nodejs`, `p/golang`, `p/r2c-security-audit`). **No Semgrep Pro packs or Pro Engine.** Override via `PENCHEFF_SEMGREP_PACKS`. |
| Semgrep Registry packs (above) | Various OSS (per pack page) | SAST rules | https://semgrep.dev/r | Pulled at scan time. Each pack's license is documented on its registry page; all listed packs are explicitly OSS at the time of writing. |
| Bandit | Apache-2.0 | Python SAST | https://github.com/PyCQA/bandit | Subprocess-only. |
| gosec | Apache-2.0 | Go SAST | https://github.com/securego/gosec | Subprocess-only. |
| Brakeman | MIT | Ruby on Rails SAST | https://github.com/presidentbeef/brakeman | Subprocess-only. |
| eslint + eslint-plugin-security | MIT / Apache-2.0 | JS / TS SAST | https://eslint.org / https://github.com/eslint-community/eslint-plugin-security | Subprocess-only via `npx`. Pinned flat config at `bench/runners/eslint_security.config.cjs`; ignores any `.eslintrc` in the target tree. |
| ffuf | MIT | Web fuzzer | https://github.com/ffuf/ffuf | Optional toolchain only. |
| subfinder | MIT | Subdomain discovery | https://github.com/projectdiscovery/subfinder | Optional toolchain only. |
| interactsh-client | MIT | Out-of-band callback verification | https://github.com/projectdiscovery/interactsh | Optional toolchain only. |
| Gitleaks | MIT | Secret scanning | https://github.com/gitleaks/gitleaks | Optional toolchain only. |
| OSV-Scanner | Apache-2.0 | Dependency vulnerability scanning | https://github.com/google/osv-scanner | Optional toolchain only. |
| YARA | BSD-3-Clause | Pattern and malware rule matching | https://github.com/VirusTotal/yara | Optional toolchain only. |
| Trivy | Apache-2.0 | Container / IaC / SCA / secrets | https://github.com/aquasecurity/trivy | Subprocess-only; pulls its own ``trivy-db`` (MIT, built from upstream feeds). |
| Checkov | Apache-2.0 | IaC policy-as-code | https://github.com/bridgecrewio/checkov | Subprocess-only. |
| wfuzz, whatweb, wafw00f, sslscan, dnsrecon, dirb, gobuster | Various OSS (see upstream) | Web and network assessment helpers | Upstream Debian package sources | Optional toolchain only; review each upstream license before distribution. |

**Removed in v0.7 (Phase 0.1):** GitHub CodeQL CLI was previously
invoked as the primary SAST engine. CodeQL is free for OSS / academic /
personal use only — commercial use on third-party code requires a
license from GitHub. To eliminate that licensing question, Pencheff
removed CodeQL entirely and replaced it with the Semgrep + Bandit + gosec
+ Brakeman + ESLint-security pack listed above.

## Vulnerability data feeds

| Feed | License | What it adds |
| --- | --- | --- |
| OSV.dev | Apache-2.0 | Per-package vulnerability list (live query) |
| NVD (National Vulnerability Database) | U.S. public domain | Per-CVE enrichment (CWE / CPE / CVSS) |
| GitHub Security Advisories (GHSA) | CC-BY-4.0 (attribution required) | Per-package advisories (via OSV mirror) |
| CISA Known Exploited Vulnerabilities | U.S. public domain | Active-exploitation flag |
| FIRST EPSS | CC-BY-4.0 (attribution required) | Daily exploit-prediction score |
| RustSec Advisory DB | CC0-1.0 | Rust crate advisories (via OSV-format mirror) |
| Go Vulnerability DB (GoVulnDB) | BSD-3-Clause | Go module advisories (via OSV-format mirror) |

## Llama Guard 3 (opt-in only)

Llama Guard 3 is *only* invoked when the operator sets
``PENCHEFF_LLAMA_GUARD_ENABLED=1``. The model is reached over an
OpenAI-compatible chat endpoint — Pencheff never bundles or
redistributes the weights. License notice surfaced in every
``JudgeResult.reason`` and reproduced here for completeness:

> Llama Guard 3 © Meta Platforms, Inc. — Llama 3 Community License
> (commercial use ≤700M MAU; attribution required).

The default judge is **IBM Granite Guardian (Apache-2.0)**, which has
none of these constraints.
"""


def _render_notices(deps: list[Dependency]) -> str:
    """Render the notices markdown deterministically, return as a string.

    Pure function: no disk I/O. ``--write-notices`` calls this then
    writes; ``--check-notices`` calls this then compares. That keeps
    the staleness check race-free.
    """
    deps_by_eco: dict[str, list[Dependency]] = {}
    for d in deps:
        deps_by_eco.setdefault(d.ecosystem, []).append(d)
    for v in deps_by_eco.values():
        v.sort(key=lambda d: d.name)

    lines: list[str] = []
    lines.append("# Third-Party Notices\n")
    lines.append(
        "This file is **auto-generated by `tools/license_audit.py "
        "--write-notices`** from the live dependency manifests + "
        "`tools/license-allowlist.txt` + the static blocks in "
        "`tools/license_audit.py`. Do not hand-edit — CI fails when "
        "this file drifts. To update the static blocks (subprocess "
        "tools, vuln feeds, the Llama Guard notice), edit "
        "``_SUBPROCESS_TOOLS_BLOCK`` in `tools/license_audit.py` and "
        "re-run `--write-notices`.\n"
    )
    lines.append(
        "Pencheff itself ships under the MIT license (see `LICENSE`). "
        "The dependencies listed below are imported directly or "
        "transitively. Subprocess-invoked external tools and ingested "
        "vulnerability feeds are documented in their own sections.\n"
    )
    eco_label = {"pypi": "Python (PyPI)", "npm": "Node (npm)"}
    for eco in sorted(deps_by_eco):
        rows = deps_by_eco[eco]
        lines.append(f"## {eco_label.get(eco, eco)} dependencies\n")
        lines.append("| Package | Version constraint | Declared license | Source manifest |")
        lines.append("| --- | --- | --- | --- |")
        for d in rows:
            lic = d.license_id or "_(unknown — see overrides)_"
            lines.append(
                f"| `{d.name}` | `{d.version}` | {lic} | `{d.source_manifest}` |"
            )
        lines.append("")

    # Static block for subprocess tools, feeds, the Llama Guard notice.
    lines.append(_SUBPROCESS_TOOLS_BLOCK)

    lines.append("## Overrides\n")
    lines.append(
        "License declarations that the manifest didn't carry are sourced "
        "from `tools/license-overrides.txt`."
    )
    # Trailing newline so editors/git don't fight over EOF.
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="License audit + NOTICES generator.")
    parser.add_argument(
        "--write-notices", action="store_true",
        help="Regenerate THIRD_PARTY_NOTICES.md and exit.",
    )
    parser.add_argument(
        "--check-notices", action="store_true",
        help="Exit non-zero if THIRD_PARTY_NOTICES.md is stale "
             "(i.e. would be different after --write-notices).",
    )
    args = parser.parse_args()

    allow = _read_allowlist()
    overrides = _read_overrides()
    deps = _python_dependencies() + _node_dependencies()
    _hydrate_licenses(deps, overrides)

    if args.write_notices:
        NOTICES_PATH.write_text(_render_notices(deps), encoding="utf-8")
        print(f"Wrote {NOTICES_PATH.relative_to(REPO_ROOT)}")
        return 0

    if args.check_notices:
        regenerated = _render_notices(deps)
        existing = NOTICES_PATH.read_text(encoding="utf-8") if NOTICES_PATH.is_file() else ""
        if existing != regenerated:
            print("THIRD_PARTY_NOTICES.md is stale — run "
                  "`python tools/license_audit.py --write-notices` and commit.")
            return 1
        return 0

    ok, bad = _audit(deps, allow)
    _print_audit(ok, bad)
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
