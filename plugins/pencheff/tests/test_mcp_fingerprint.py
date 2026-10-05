from pencheff.modules.mcp_scan.manifest import McpManifest
from pencheff.modules.mcp_scan import fingerprint as fp


def _mf(**kw):
    base = dict(transport="stdio", endpoint="stdio:test")
    base.update(kw); return McpManifest(**base)


def test_flags_vulnerable_mcp_remote_in_command():
    mf = _mf(transport="stdio", endpoint="stdio:npx mcp-remote@0.1.10")
    findings = fp.fingerprint(mf, command=["npx", "mcp-remote@0.1.10"])
    assert any("CVE-2025-6514" in (f.references and " ".join(f.references)) or "6514" in f.title or
               "6514" in (f.metadata or {}).get("cve", "") for f in findings)


def test_clean_command_no_findings():
    mf = _mf(endpoint="stdio:npx safe-server")
    assert fp.fingerprint(mf, command=["npx", "safe-server"]) == []


def test_flags_vulnerable_server_version():
    mf = _mf(server_name="mcp-inspector", server_version="0.13.0")
    findings = fp.fingerprint(mf, command=None)
    assert any((f.metadata or {}).get("cve") == "CVE-2025-49596" for f in findings)


def test_patched_version_not_flagged():
    mf = _mf(server_name="mcp-inspector", server_version="0.14.1")
    assert fp.fingerprint(mf, command=None) == []
