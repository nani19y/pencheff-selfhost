import asyncio
from pencheff.modules.voice_scan.transport_probes import run_transport_probes


class _Resp:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
    def json(self): return {}


def test_no_http_get_is_noop():
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"}
    findings = asyncio.run(run_transport_probes(cfg, http_get=None, oast=None))
    assert findings == []


def test_unauthenticated_endpoint_flagged():
    async def http_get(url, **kw): return _Resp(status_code=200, text="ok")
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"}
    findings = asyncio.run(run_transport_probes(cfg, http_get=http_get, oast=None))
    assert any(f.metadata.get("technique") == "voice:exposed-endpoint" for f in findings)


def test_auth_required_endpoint_not_flagged_as_exposed():
    async def http_get(url, **kw): return _Resp(status_code=401, text="unauthorized")
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"}
    findings = asyncio.run(run_transport_probes(cfg, http_get=http_get, oast=None))
    assert not any(f.metadata.get("technique") == "voice:exposed-endpoint" for f in findings)


def test_post_only_endpoint_surfaces_auth_required():
    # STT endpoints are POST-only: GET returns 405, so the auth posture is only
    # visible via a POST. Without creds this must surface the "scan blind" INFO.
    async def http_get(url, **kw): return _Resp(status_code=405, text="method not allowed")
    async def http_post(url, **kw): return _Resp(status_code=401, text="unauthorized")
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"}
    findings = asyncio.run(run_transport_probes(cfg, http_get=http_get, http_post=http_post, oast=None))
    assert any(f.metadata.get("technique") == "voice:auth-required" for f in findings)


def test_post_reachable_without_auth_flagged():
    async def http_get(url, **kw): return _Resp(status_code=404, text="not found")
    async def http_post(url, **kw): return _Resp(status_code=200, text="{}")
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt"}
    findings = asyncio.run(run_transport_probes(cfg, http_get=http_get, http_post=http_post, oast=None))
    assert any(f.metadata.get("technique") == "voice:exposed-endpoint" for f in findings)


def test_rejected_credentials_surfaced():
    # Creds supplied (headers) but the authenticated POST still 403s → wrong auth
    # scheme; must surface 'auth-rejected', not grade the blind scan clean.
    async def http_get(url, **kw): return _Resp(status_code=405)
    async def http_post(url, **kw): return _Resp(status_code=403)
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt",
           "credentials": {"headers": {"Authorization": "Bearer x"}}}
    findings = asyncio.run(run_transport_probes(cfg, http_get=http_get, http_post=http_post, oast=None))
    assert any(f.metadata.get("technique") == "voice:auth-rejected" for f in findings)


def test_valid_credentials_no_auth_rejected():
    # Creds accepted (400 = bad audio, not an auth error) → no auth-rejected noise.
    async def http_get(url, **kw): return _Resp(status_code=405)
    async def http_post(url, **kw): return _Resp(status_code=400)
    cfg = {"kind": "voice", "source_type": "stt_endpoint", "url": "https://h/stt",
           "credentials": {"headers": {"api-subscription-key": "sk_valid"}}}
    findings = asyncio.run(run_transport_probes(cfg, http_get=http_get, http_post=http_post, oast=None))
    assert not any(f.metadata.get("technique") == "voice:auth-rejected" for f in findings)
