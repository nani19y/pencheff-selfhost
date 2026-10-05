"""Finding → LSP diagnostic mapper.

Pencheff findings come in three flavours that can land in a code editor:

  * **SCA**  — manifest path + package name. We diagnose the line in the
    manifest that mentions the package.
  * **SAST** — file path + line in evidence. We diagnose that exact line.
  * **DAST** — URL path. We attempt route-handler resolution if the
    endpoint maps to a known route file (best-effort); otherwise the
    finding is surfaced via the workspace symbol channel only.

Severities map to LSP DiagnosticSeverity per the spec:
  1 = Error, 2 = Warning, 3 = Information, 4 = Hint.

The converter is pure — it takes a parsed Pencheff finding (the dict
shape produced by ``Finding.to_dict()``) plus a workspace root and
returns a list of ``(uri, diagnostic_dict)`` tuples ready to ship over
the wire. Tests assert against this contract directly.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


_SEVERITY_MAP: dict[str, int] = {
    "critical": 1,  # Error
    "high":     1,  # Error — IDEs visually distinguish via the message
    "medium":   2,  # Warning
    "low":      3,  # Information
    "info":     4,  # Hint
}


def severity_to_lsp(sev: str) -> int:
    """Pencheff severity label → LSP DiagnosticSeverity."""
    return _SEVERITY_MAP.get((sev or "").lower(), 3)


def _path_to_uri(p: Path) -> str:
    """Build a ``file://`` URI for an absolute path. Normalises Windows
    drive paths so the LSP client matches its open documents.
    """
    s = p.resolve().as_posix()
    if not s.startswith("/"):
        # Windows: posix-style path is "C:/Users/..." — LSP wants
        # "file:///C:/Users/..."
        return f"file:///{s}"
    return f"file://{s}"


def _find_line_for_package(manifest: Path, pkg: str) -> int:
    """Locate the 0-indexed line where ``pkg`` first appears in the
    manifest. Falls back to line 0 (first line) when no match — better
    to surface the diagnostic somewhere visible than to drop it.
    """
    if not manifest.is_file() or not pkg:
        return 0
    try:
        text = manifest.read_text(errors="replace")
    except OSError:
        return 0
    pat = re.compile(rf"(^|[\s\"'<,/]){re.escape(pkg)}([\s\"'<,/=:>~^@]|$)")
    for idx, line in enumerate(text.splitlines()):
        if pat.search(line):
            return idx
    return 0


def _line_for_sast(evidence: list[dict] | None) -> int | None:
    """Pull the line number from SAST evidence if the runner planted one
    in the autofix payload (semgrep does, codeql does, bandit does)."""
    for ev in evidence or []:
        autofix = ev.get("autofix") or {}
        line = autofix.get("start_line")
        if isinstance(line, int) and line >= 1:
            return line - 1  # LSP is 0-indexed
    return None


def _is_url(s: str) -> bool:
    if not s:
        return False
    parsed = urlparse(s)
    return bool(parsed.scheme and parsed.netloc and parsed.scheme not in ("file", "repo"))


def finding_to_diagnostics(
    finding: dict[str, Any],
    workspace_root: Path,
) -> list[tuple[str, dict[str, Any]]]:
    """Convert a single Pencheff finding to ``(uri, lsp_diagnostic)`` pairs.

    Returns ``[]`` when the finding cannot be mapped to a workspace file
    (e.g. a DAST finding against a remote URL that has no local repo).
    """
    endpoint = (finding.get("endpoint") or "").strip()
    if not endpoint or _is_url(endpoint):
        return []
    # SAST findings encode "repo://name/path/to/file.py" — strip the prefix.
    if endpoint.startswith("repo://"):
        body = endpoint[len("repo://"):]
        _name, _, rel = body.partition("/")
        endpoint = rel
    file_path = (workspace_root / endpoint).resolve()
    try:
        file_path.relative_to(workspace_root.resolve())
    except (ValueError, OSError):
        return []
    if not file_path.is_file():
        return []
    # Choose the line:
    #   1. SAST autofix payload (most accurate)
    #   2. SCA: search the manifest for the package name
    #   3. Fallback: first line
    line = _line_for_sast(finding.get("evidence"))
    if line is None:
        # SCA: parameter shape is "ecosystem:name@version".
        param = finding.get("parameter") or ""
        if ":" in param and "@" in param:
            _, rest = param.split(":", 1)
            pkg = rest.split("@", 1)[0]
            line = _find_line_for_package(file_path, pkg)
        else:
            line = 0
    severity = severity_to_lsp(finding.get("severity", ""))
    title = finding.get("title") or "Pencheff finding"
    description = (finding.get("description") or "").strip()
    cve_id = ""
    for ev in finding.get("evidence") or []:
        autofix = ev.get("autofix") or {}
        if autofix.get("advisory_id"):
            cve_id = f" [{autofix['advisory_id']}]"
            break
    diagnostic = {
        "range": {
            "start": {"line": line, "character": 0},
            "end":   {"line": line, "character": 200},
        },
        "severity": severity,
        "code":     finding.get("cwe") or finding.get("owasp", "").split(":")[0] or "PENCHEFF",
        "source":   "pencheff",
        "message":  f"{title}{cve_id}\n\n{description[:600]}".rstrip(),
        # IDE-side metadata that VSCode + LSP4IJ can use to render the
        # `Quick Fix` lightbulb when a fix proposal exists.
        "data": {
            "finding_id":  finding.get("id"),
            "category":    finding.get("category"),
            "owasp":       finding.get("owasp"),
            "remediation": finding.get("remediation"),
        },
    }
    return [(_path_to_uri(file_path), diagnostic)]


def findings_to_diagnostics_by_uri(
    findings: list[dict[str, Any]],
    workspace_root: Path,
) -> dict[str, list[dict[str, Any]]]:
    """Bulk-convert findings, grouped by URI for ``publishDiagnostics``."""
    out: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        for uri, diag in finding_to_diagnostics(f, workspace_root):
            out.setdefault(uri, []).append(diag)
    return out
