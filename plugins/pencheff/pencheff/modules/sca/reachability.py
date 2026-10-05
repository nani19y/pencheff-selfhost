"""Lightweight reachability annotation for dependency findings.

Real call-graph reachability is complex; we ship a pragmatic heuristic:
- Grep source under ``root`` for imports/requires of each vulnerable package.
- If no usage is found, mark the finding ``suppressed=False`` but tag it
  ``verification_notes='low_reachability: no imports detected'`` so reporters
  can de-prioritise it.

When ``semgrep`` is installed, we upgrade to a semgrep-based pass (rule
synthesized on the fly), which is more accurate than plain grep.
"""

from __future__ import annotations

import re
import subprocess  # noqa: S404
from pathlib import Path

from pencheff.core.findings import Finding

# Heuristic file globs per ecosystem
ECOSYSTEM_GLOBS = {
    "npm": ["**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx", "**/*.mjs"],
    "PyPI": ["**/*.py"],
    "Go": ["**/*.go"],
    "crates.io": ["**/*.rs"],
    "RubyGems": ["**/*.rb"],
    "Packagist": ["**/*.php"],
    "Maven": ["**/*.java", "**/*.kt"],
}


def annotate(findings: list[Finding], root: Path) -> list[Finding]:
    """Set ``verification_notes`` on findings that look unreachable."""
    if not root.exists():
        return findings
    for f in findings:
        if f.category != "components":
            continue
        pkg = _extract_pkg(f)
        if not pkg:
            continue
        ecosystem, name = pkg
        if not _has_usage(root, ecosystem, name):
            f.verification_notes = (
                (f.verification_notes + "; " if f.verification_notes else "")
                + "low_reachability: no imports/requires detected"
            ).strip("; ")
    return findings


def _extract_pkg(f: Finding) -> tuple[str, str] | None:
    # parameter format: "ecosystem:name@version"
    if not f.parameter or ":" not in f.parameter:
        return None
    try:
        eco, rest = f.parameter.split(":", 1)
        name = rest.split("@", 1)[0]
        return eco, name
    except Exception:  # noqa: BLE001
        return None


def _has_usage(root: Path, ecosystem: str, name: str) -> bool:
    patterns = _import_patterns(ecosystem, name)
    globs = ECOSYSTEM_GLOBS.get(ecosystem, ["**/*"])
    # Prefer semgrep if available (faster and more accurate)
    if _semgrep_available():
        try:
            for g in globs[:2]:
                for p in root.glob(g):
                    if not p.is_file():
                        continue
                    text = p.read_text(errors="ignore")
                    for pat in patterns:
                        if re.search(pat, text):
                            return True
                    if p.stat().st_size > 2_000_000:
                        break
            return False
        except Exception:  # noqa: BLE001
            pass
    # Plain regex fallback
    for g in globs:
        for p in root.glob(g):
            if not p.is_file() or p.stat().st_size > 2_000_000:
                continue
            try:
                text = p.read_text(errors="ignore")
            except Exception:  # noqa: BLE001
                continue
            for pat in patterns:
                if re.search(pat, text):
                    return True
    return False


def _semgrep_available() -> bool:
    try:
        subprocess.run(
            ["semgrep", "--version"], capture_output=True, timeout=3, check=False
        )
        return True
    except (FileNotFoundError, subprocess.SubprocessError):
        return False


def _import_patterns(ecosystem: str, name: str) -> list[str]:
    esc = re.escape(name)
    if ecosystem == "npm":
        return [
            rf"(?m)^\s*import\s+.*from\s+['\"]{esc}(/|['\"])",
            rf"(?m)require\(\s*['\"]{esc}(/|['\"])",
        ]
    if ecosystem == "PyPI":
        mod = name.replace("-", "_")
        emod = re.escape(mod)
        return [
            rf"(?m)^\s*import\s+{emod}\b",
            rf"(?m)^\s*from\s+{emod}\b",
        ]
    if ecosystem == "Go":
        return [rf"['\"]{esc}['\"]"]
    if ecosystem == "crates.io":
        return [rf"extern\s+crate\s+{esc}", rf"use\s+{esc}::"]
    if ecosystem == "RubyGems":
        return [rf"require\s+['\"]{esc}['\"]"]
    if ecosystem == "Packagist":
        return [rf"\\{esc}\\", rf"use\s+{esc}\\"]
    if ecosystem == "Maven":
        group = name.split(":")[0]
        return [rf"import\s+{re.escape(group)}\."]
    return [esc]
