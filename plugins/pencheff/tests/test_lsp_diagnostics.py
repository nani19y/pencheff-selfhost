"""Tests for ``pencheff.lsp.diagnostics`` — the finding-to-LSP-diagnostic
mapper. Covers SCA / SAST / DAST routing, severity mapping, and the
contract that remote-URL findings produce no diagnostics (they have no
local file to attach to).
"""
from __future__ import annotations

import pytest

from pencheff.lsp.diagnostics import (
    finding_to_diagnostics,
    findings_to_diagnostics_by_uri,
    severity_to_lsp,
)


@pytest.fixture
def workspace(tmp_path):
    """A workspace with a couple of manifests + a source file the LSP
    can resolve findings against."""
    (tmp_path / "requirements.txt").write_text(
        "click==8.1.0\n"
        "flask==2.0.0\n"
        "requests>=2.20\n"
    )
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"lodash": "^4.0.0", "axios": "^1.0.0"}}\n'
    )
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(
        "def login(user, pwd):\n"
        "    sql = f'select * from users where u={user}'\n"
        "    return db.exec(sql)\n"
    )
    return tmp_path


def _sca_finding(pkg: str, ecosystem: str = "PyPI", manifest: str = "requirements.txt"):
    return {
        "id":        "f-1",
        "title":     f"{pkg} 2.0.0 — CVE-2024-9999",
        "severity":  "high",
        "category":  "components",
        "owasp":     "A06: Vulnerable & Outdated Components",
        "endpoint":  manifest,
        "parameter": f"{ecosystem}:{pkg}@2.0.0",
        "description": f"{pkg} is vulnerable to RCE.",
        "remediation": f"Upgrade {pkg} to 2.3.3.",
        "evidence": [{
            "request_method": "OSV",
            "autofix": {
                "ecosystem":    ecosystem,
                "package":      pkg,
                "fix_version":  "2.3.3",
                "advisory_id":  "CVE-2024-9999",
            },
        }],
    }


def _sast_finding(rel: str, line: int):
    return {
        "id":        "f-2",
        "title":     "SQL injection in login()",
        "severity":  "critical",
        "category":  "injection",
        "owasp":     "A03: Injection",
        "endpoint":  f"repo://acme-app/{rel}",
        "parameter": str(line),
        "description": "User-controlled `user` flows into a raw SQL string.",
        "evidence": [{
            "request_method": "SAST_AUTOFIX",
            "autofix": {"start_line": line, "kind": "text_replace"},
        }],
    }


def test_severity_mapping():
    assert severity_to_lsp("critical") == 1
    assert severity_to_lsp("high") == 1
    assert severity_to_lsp("medium") == 2
    assert severity_to_lsp("low") == 3
    assert severity_to_lsp("info") == 4
    assert severity_to_lsp("anything-else") == 3


def test_sca_finding_locates_package_line(workspace):
    diags = finding_to_diagnostics(_sca_finding("flask"), workspace)
    assert len(diags) == 1
    uri, d = diags[0]
    assert uri.startswith("file://") and uri.endswith("/requirements.txt")
    # `flask` is on line 2 (0-indexed: 1).
    assert d["range"]["start"]["line"] == 1
    assert d["severity"] == 1  # high → Error
    assert "flask" in d["message"].lower()
    assert "[CVE-2024-9999]" in d["message"]


def test_sca_finding_npm_package(workspace):
    diags = finding_to_diagnostics(
        _sca_finding("lodash", "npm", "package.json"), workspace,
    )
    assert len(diags) == 1
    uri, d = diags[0]
    assert uri.endswith("/package.json")
    # lodash appears on the dependencies line.
    assert d["range"]["start"]["line"] >= 0


def test_sca_missing_package_falls_back_to_first_line(workspace):
    f = _sca_finding("ghost-package")  # not in the manifest
    diags = finding_to_diagnostics(f, workspace)
    # We still surface the diagnostic — point it at the file itself, not nowhere.
    assert len(diags) == 1
    uri, d = diags[0]
    assert d["range"]["start"]["line"] == 0


def test_sast_finding_uses_autofix_line(workspace):
    diags = finding_to_diagnostics(_sast_finding("src/app.py", 2), workspace)
    assert len(diags) == 1
    uri, d = diags[0]
    assert uri.endswith("/src/app.py")
    # autofix says start_line=2 (1-indexed) → LSP line 1 (0-indexed).
    assert d["range"]["start"]["line"] == 1
    assert d["severity"] == 1


def test_url_endpoint_produces_no_diagnostic(workspace):
    f = {
        "id": "f-3", "title": "Reflected XSS",
        "severity": "high", "category": "xss",
        "owasp": "A03: Injection",
        "endpoint": "https://target.example.com/search?q=foo",
        "parameter": "q",
        "evidence": [],
    }
    assert finding_to_diagnostics(f, workspace) == []


def test_path_outside_workspace_is_dropped(workspace, tmp_path):
    other = tmp_path.parent  # parent of tmp_path is outside the workspace
    f = _sast_finding("../escape.py", 1)
    diags = finding_to_diagnostics(f, workspace)
    assert diags == []


def test_findings_grouped_by_uri(workspace):
    findings = [
        _sca_finding("click"),
        _sca_finding("flask"),
        _sast_finding("src/app.py", 2),
    ]
    grouped = findings_to_diagnostics_by_uri(findings, workspace)
    # Two manifest hits + one source-file hit.
    assert len(grouped) == 2
    by_basename = {uri.rsplit("/", 1)[-1]: diags for uri, diags in grouped.items()}
    assert len(by_basename["requirements.txt"]) == 2
    assert len(by_basename["app.py"]) == 1
