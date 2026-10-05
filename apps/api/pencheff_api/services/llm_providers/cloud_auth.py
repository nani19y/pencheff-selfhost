# apps/api/pencheff_api/services/llm_providers/cloud_auth.py
"""Cloud auth for BYO-LLM Bedrock + Vertex adapters — api-side, no boto3.
SigV4 is stdlib hmac/hashlib; Vertex uses google-auth (already a dependency).
The google-auth symbols are module-level so tests can monkeypatch them."""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json as _json
from urllib.parse import urlsplit

# Indirection points for tests (monkeypatched in test_llm_cloud_auth).
try:  # pragma: no cover - import guard
    from google.oauth2 import service_account as _service_account
    from google.auth.transport.requests import Request as _AuthRequest
except Exception:  # pragma: no cover
    _service_account = None
    _AuthRequest = None


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def sigv4_headers(*, method: str, url: str, region: str, service: str, body: bytes,
                  access_key: str, secret_key: str, session_token: str | None = None,
                  now: _dt.datetime | None = None) -> dict[str, str]:
    """AWS Signature V4 headers for a request. ``now`` injectable for tests.
    The canonical URI is taken verbatim from ``url``'s path, so the caller must
    pass the same (percent-encoded) path it will send the request to."""
    now = now or _dt.datetime.now(_dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    parts = urlsplit(url)
    host = parts.netloc
    canonical_uri = parts.path or "/"
    canonical_qs = parts.query  # bedrock converse has none; signed as-is
    payload_hash = hashlib.sha256(body).hexdigest()

    headers_to_sign = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    if session_token:
        headers_to_sign["x-amz-security-token"] = session_token
    signed_headers = ";".join(sorted(headers_to_sign))
    canonical_headers = "".join(f"{k}:{headers_to_sign[k]}\n" for k in sorted(headers_to_sign))

    canonical_request = "\n".join(
        [method, canonical_uri, canonical_qs, canonical_headers, signed_headers, payload_hash]
    )
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope,
         hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()]
    )
    k_date = _sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    out = {
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                          f"SignedHeaders={signed_headers}, Signature={signature}"),
        "X-Amz-Date": amz_date,
        "X-Amz-Content-Sha256": payload_hash,
    }
    if session_token:
        out["X-Amz-Security-Token"] = session_token
    return out


def vertex_access_token(service_account_json, scopes=("https://www.googleapis.com/auth/cloud-platform",)) -> str:
    """Mint an OAuth2 access token from a service-account JSON (dict or str)."""
    if _service_account is None:  # pragma: no cover
        raise RuntimeError("google-auth is not installed")
    info = _json.loads(service_account_json) if isinstance(service_account_json, str) else service_account_json
    cred = _service_account.Credentials.from_service_account_info(info, scopes=list(scopes))
    cred.refresh(_AuthRequest())
    return cred.token
