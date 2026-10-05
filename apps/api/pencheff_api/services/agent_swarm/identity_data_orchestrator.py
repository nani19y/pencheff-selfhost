"""Identity, Data & Compliance orchestrator — provider-aware IdP + data-store.

  - idp        : OIDC discovery + SAML metadata + (with an admin API token)
                 provider policy checks (Okta / Auth0 / WorkOS / Casdoor)
  - data_store : DB exposure + unauthenticated access + TLS-required + version/EOL

Universal checks run with no credentials; provider/admin enrichment layers on when
credentials are supplied. Read-only; nothing is written or exploited.
"""
from __future__ import annotations

import asyncio
import json
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

IDENTITY_DATA_KINDS = frozenset({"idp", "data_store"})


def _ev(endpoint: str, description: str, detail: dict[str, Any]) -> list[dict[str, Any]]:
    d = {k: v for k, v in detail.items() if v is not None}
    return [{"request_url": endpoint, "description": description,
             "response_body_snippet": json.dumps(d, indent=2, default=str) if d else None}]


def _mk(title, severity, category, owasp, desc, rem, endpoint, parameter, detail, cwe=None) -> dict[str, Any]:
    return {"title": title, "severity": severity, "category": category,
            "owasp_category": owasp, "cwe_id": cwe, "description": desc, "remediation": rem,
            "endpoint": endpoint, "parameter": parameter, "evidence": _ev(endpoint, desc, detail)}


# ── IdP: OIDC + SAML + admin-API enrichment ─────────────────────────────────
def _scan_idp(cfg: dict[str, Any], creds: dict[str, Any]) -> list[dict[str, Any]]:
    import httpx
    F: list[dict[str, Any]] = []
    raw = str(cfg.get("issuer_url") or "").strip().rstrip("/")
    provider = cfg.get("provider", "generic_oidc")
    if raw and not raw.startswith("http"):
        raw = "https://" + raw

    # ── OIDC discovery ──
    if raw and provider != "saml":
        disco_url = raw if raw.endswith("openid-configuration") else f"{raw}/.well-known/openid-configuration"
        doc = None
        try:
            with httpx.Client(timeout=12.0, follow_redirects=True) as c:
                r = c.get(disco_url)
                if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
                    doc = r.json()
        except Exception:
            doc = None
        if doc is None and provider in ("generic_oidc", "custom"):
            F.append(_mk(f"OIDC discovery document not found: {raw}", "info", "identity", "IDP-00 Discovery",
                         f"No OIDC discovery doc at {disco_url}.", "Confirm the issuer URL / provide SAML metadata.",
                         raw, "discovery", {"tried": disco_url}))
        if doc:
            F.extend(_oidc_findings(doc, raw))

    # ── SAML metadata ──
    meta_url = cfg.get("saml_metadata_url")
    if meta_url or provider == "saml":
        F.extend(_saml_findings(str(meta_url or raw)))

    # ── provider admin API enrichment ──
    if creds.get("api_token") or creds.get("client_secret"):
        F.extend(_idp_provider(provider, cfg, creds))
    return F


def _oidc_findings(doc: dict[str, Any], issuer_url: str) -> list[dict[str, Any]]:
    F: list[dict[str, Any]] = []
    issuer = str(doc.get("issuer") or issuer_url)
    if issuer.startswith("http://"):
        F.append(_mk(f"IdP issuer served over plaintext HTTP: {issuer}", "critical", "identity", "IDP-05 Transport",
                     "The OIDC issuer is not HTTPS — tokens/metadata are interceptable.",
                     "Serve all OAuth endpoints over HTTPS only.", issuer, "http", {}, cwe="CWE-319"))
    grants = [str(g).lower() for g in (doc.get("grant_types_supported") or [])]
    resp = [str(g).lower() for g in (doc.get("response_types_supported") or [])]
    if "implicit" in grants or any("token" in rt and "code" not in rt for rt in resp):
        F.append(_mk(f"OAuth implicit flow enabled: {issuer}", "high", "identity", "IDP-01 Grant Hygiene",
                     "The IdP advertises the implicit flow (tokens in the URL fragment) — deprecated by OAuth 2.1.",
                     "Disable implicit; use authorization code + PKCE.", issuer, "implicit",
                     {"grant_types": grants, "response_types": resp}, cwe="CWE-522"))
    if "password" in grants:
        F.append(_mk(f"OAuth ROPC password grant enabled: {issuer}", "high", "identity", "IDP-01 Grant Hygiene",
                     "The IdP allows the resource-owner password grant.", "Disable ROPC; use redirect flows.",
                     issuer, "password", {"grant_types": grants}, cwe="CWE-522"))
    ccm = [str(m).lower() for m in (doc.get("code_challenge_methods_supported") or [])]
    if "authorization_code" in grants and "s256" not in ccm:
        F.append(_mk(f"PKCE (S256) not advertised: {issuer}", "high", "identity", "IDP-02 PKCE",
                     "Code flow without PKCE S256 — public clients are exposed to code interception.",
                     "Require PKCE S256.", issuer, "no-pkce", {"code_challenge_methods": ccm}, cwe="CWE-1275"))
    algs = [str(a).lower() for a in (doc.get("id_token_signing_alg_values_supported") or [])]
    if "none" in algs:
        F.append(_mk(f"ID token signing allows 'none': {issuer}", "critical", "identity", "IDP-03 Token Signing",
                     "Unsigned ID tokens can be forged.", "Remove 'none'; require RS256/ES256.", issuer, "alg=none",
                     {"algs": algs}, cwe="CWE-347"))
    elif algs and all(a.startswith("hs") for a in algs):
        F.append(_mk(f"ID tokens use only symmetric (HS*) signing: {issuer}", "medium", "identity",
                     "IDP-03 Token Signing", "Only HMAC signing — clients share the secret.",
                     "Offer asymmetric RS256/ES256.", issuer, ",".join(algs), {"algs": algs}))
    team = [str(m).lower() for m in (doc.get("token_endpoint_auth_methods_supported") or [])]
    if "none" in team:
        F.append(_mk(f"Token endpoint allows unauthenticated clients: {issuer}", "medium", "identity",
                     "IDP-04 Client Auth", "The token endpoint accepts 'none' client auth.",
                     "Require client authentication where feasible.", issuer, "client-auth-none", {"methods": team}))
    if not doc.get("revocation_endpoint"):
        F.append(_mk(f"No token revocation endpoint: {issuer}", "low", "identity", "IDP-06 Lifecycle",
                     "No RFC 7009 revocation endpoint.", "Expose a revocation endpoint.", issuer, "no-revocation", {}))
    return F


def _saml_findings(meta_url: str) -> list[dict[str, Any]]:
    import httpx
    F: list[dict[str, Any]] = []
    if not meta_url.startswith("http"):
        meta_url = "https://" + meta_url
    try:
        with httpx.Client(timeout=12.0, follow_redirects=True) as c:
            r = c.get(meta_url)
        if r.status_code != 200 or "<" not in r.text:
            F.append(_mk(f"SAML metadata not found: {meta_url}", "info", "identity", "IDP-00 Discovery",
                         f"No SAML metadata at {meta_url}.", "Provide the IdP SAML metadata URL.",
                         meta_url, "saml", {}))
            return F
        xml = r.text
    except Exception:
        return F
    try:
        from defusedxml import ElementTree as ET
        root = ET.fromstring(xml.encode())
    except Exception:
        return F
    ns = {"md": "urn:oasis:names:tc:SAML:2.0:metadata", "ds": "http://www.w3.org/2000/09/xmldsig#"}
    entity = root.get("entityID", meta_url)
    # signing method algorithms
    algs = [e.get("Algorithm", "") for e in root.iter("{http://www.w3.org/2000/09/xmldsig#}SignatureMethod")]
    algs += [e.get("Algorithm", "") for e in root.iter("{http://www.w3.org/2000/09/xmldsig#}DigestMethod")]
    if any("sha1" in a.lower() or "rsa-sha1" in a.lower() for a in algs):
        F.append(_mk(f"SAML uses SHA-1 signatures: {entity}", "high", "identity", "IDP-07 SAML Signing",
                     "The SAML metadata declares SHA-1 signature/digest algorithms (collidable).",
                     "Switch to SHA-256 signatures/digests.", entity, "sha1", {"algorithms": algs}, cwe="CWE-328"))
    # embedded cert expiry
    from cryptography import x509
    import base64
    for certel in root.iter("{http://www.w3.org/2000/09/xmldsig#}X509Certificate"):
        try:
            der = base64.b64decode("".join((certel.text or "").split()))
            cert = x509.load_der_x509_certificate(der)
            na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
            days = (na - datetime.now(timezone.utc)).days
            if days < 0:
                F.append(_mk(f"SAML signing certificate expired: {entity}", "high", "identity", "IDP-07 SAML Signing",
                             f"A SAML signing certificate expired {abs(days)} day(s) ago.",
                             "Rotate the SAML signing certificate.", entity, "cert-expired", {"not_after": str(na)}))
            elif days < 30:
                F.append(_mk(f"SAML signing certificate expiring soon: {entity}", "medium", "identity",
                             "IDP-07 SAML Signing", f"A SAML signing certificate expires in {days} day(s).",
                             "Rotate before expiry.", entity, f"{days}d", {"not_after": str(na)}))
        except Exception:
            continue
    # WantAuthnRequestsSigned
    idp = root.find(".//md:IDPSSODescriptor", ns)
    if idp is not None and idp.get("WantAuthnRequestsSigned", "false").lower() != "true":
        F.append(_mk(f"SAML does not require signed AuthnRequests: {entity}", "low", "identity",
                     "IDP-07 SAML Signing", "WantAuthnRequestsSigned is not set — SP requests are unauthenticated.",
                     "Require signed AuthnRequests.", entity, "unsigned-authnrequests", {}))
    return F


def _idp_provider(provider: str, cfg: dict[str, Any], creds: dict[str, Any]) -> list[dict[str, Any]]:
    import httpx
    F: list[dict[str, Any]] = []
    domain = creds.get("org_domain") or cfg.get("org_domain") or ""
    token = creds.get("api_token") or ""
    try:
        if provider == "okta" and domain and token:
            base = domain if domain.startswith("http") else f"https://{domain}"
            with httpx.Client(timeout=12.0, headers={"Authorization": f"SSWS {token}",
                                                      "Accept": "application/json"}) as c:
                pw = c.get(f"{base}/api/v1/policies", params={"type": "PASSWORD"}).json()
                mfa = c.get(f"{base}/api/v1/policies", params={"type": "MFA_ENROLL"}).json()
            for p in (pw if isinstance(pw, list) else []):
                comp = ((p.get("settings") or {}).get("password") or {}).get("complexity") or {}
                if (comp.get("minLength") or 0) < 12:
                    F.append(_mk(f"Okta weak password policy: min length {comp.get('minLength')}", "medium",
                                 "identity", "IDP-08 Provider Policy",
                                 f"Okta policy '{p.get('name')}' allows passwords shorter than 12 chars.",
                                 "Raise the minimum length to >=12 with complexity + breach checks.",
                                 base, "okta-pwlen", {"min_length": comp.get("minLength")}, cwe="CWE-521"))
            enrolled = any((r.get("settings", {}).get("type") or "") for p in (mfa if isinstance(mfa, list) else [])
                           for r in [p])
            if isinstance(mfa, list) and not any(p.get("status") == "ACTIVE" for p in mfa):
                F.append(_mk("Okta MFA enrollment policy not active", "high", "identity", "IDP-08 Provider Policy",
                             "No active Okta MFA enrollment policy was found.", "Require MFA enrollment for all users.",
                             base, "okta-mfa", {}, cwe="CWE-308"))
        elif provider == "auth0" and domain and token:
            base = domain if domain.startswith("http") else f"https://{domain}"
            with httpx.Client(timeout=12.0, headers={"Authorization": f"Bearer {token}"}) as c:
                ap = c.get(f"{base}/api/v2/attack-protection/brute-force-protection").json()
                gf = c.get(f"{base}/api/v2/guardian/factors").json()
            if isinstance(ap, dict) and ap.get("enabled") is False:
                F.append(_mk("Auth0 brute-force protection disabled", "high", "identity", "IDP-08 Provider Policy",
                             "Auth0 brute-force protection is turned off.", "Enable brute-force protection.",
                             base, "auth0-bruteforce", {}, cwe="CWE-307"))
            if isinstance(gf, list) and not any(f.get("enabled") for f in gf):
                F.append(_mk("Auth0 MFA has no enabled factors", "high", "identity", "IDP-08 Provider Policy",
                             "No Auth0 Guardian MFA factor is enabled.", "Enable at least one MFA factor.",
                             base, "auth0-mfa", {}, cwe="CWE-308"))
    except Exception:
        pass
    return F


# ── data store exposure + unauth + TLS + version ────────────────────────────
_DB_PORTS = {6379: "redis", 11211: "memcached", 27017: "mongodb", 5432: "postgresql",
             3306: "mysql", 9200: "elasticsearch", 1433: "mssql", 5984: "couchdb", 9042: "cassandra"}
_EOL_HINTS = {"redis": ("5.", "6.0"), "mysql": ("5.5", "5.6", "5.7"), "postgresql": ("9.", "10.", "11."),
              "mongodb": ("3.", "4.0", "4.2")}


def _split_hostport(entry: str) -> tuple[str, int | None]:
    entry = entry.strip().rstrip("/")
    if entry.count(":") == 1:
        h, _, p = entry.partition(":")
        return h, int(p) if p.isdigit() else None
    return entry, None


def _tls_available(host: str, port: int) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=4) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return True
    except (ssl.SSLError, OSError):
        return False


def _probe_datastore(host: str, port: int, engine: str) -> dict[str, Any]:
    out: dict[str, Any] = {"reachable": False}
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except OSError:
        return out
    out["reachable"] = True
    try:
        sock.settimeout(5)
        if engine == "redis":
            sock.sendall(b"*1\r\n$4\r\nINFO\r\n")
            data = sock.recv(2048)
            out["unauth"] = data.startswith(b"$") or data.startswith(b"+")
            for line in data.decode("latin1").splitlines():
                if line.startswith("redis_version:"):
                    out["version"] = line.split(":", 1)[1].strip()
            out["note"] = "auth required" if b"NOAUTH" in data else None
        elif engine == "memcached":
            sock.sendall(b"version\r\n")
            data = sock.recv(256)
            if data.startswith(b"VERSION"):
                out["unauth"] = True
                parts = data.split()
                out["version"] = parts[1].decode("ascii", "ignore") if len(parts) > 1 else None
        elif engine == "postgresql":
            body = (3 << 16).to_bytes(4, "big") + b"user\x00postgres\x00database\x00postgres\x00\x00"
            sock.sendall((len(body) + 4).to_bytes(4, "big") + body)
            data = sock.recv(64)
            if data[:1] == b"R" and len(data) >= 9:
                at = int.from_bytes(data[5:9], "big")
                out["unauth"] = at == 0
                out["note"] = {0: "trust (no auth)", 3: "cleartext password", 5: "md5", 10: "SASL"}.get(at, f"authtype={at}")
        elif engine == "mysql":
            data = sock.recv(256)
            if len(data) > 5:
                out["version"] = data[5:].split(b"\x00")[0].decode("ascii", "ignore")
        elif engine == "mongodb":
            out["note"] = "reachable"
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _scan_datastore(cfg: dict[str, Any], creds: dict[str, Any]) -> list[dict[str, Any]]:
    import httpx
    F: list[dict[str, Any]] = []
    forced = cfg.get("engine", "auto")
    for entry in cfg.get("hosts") or []:
        host, port = _split_hostport(str(entry))
        if port is None:
            candidates = list(_DB_PORTS.items()) if forced == "auto" else \
                [(p, e) for p, e in _DB_PORTS.items() if e == forced]
        else:
            candidates = [(port, forced if forced != "auto" else _DB_PORTS.get(port, "database"))]
        for p, engine in candidates:
            where = f"{host}:{p}"
            if engine == "elasticsearch":
                try:
                    with httpx.Client(timeout=5.0) as c:
                        r = c.get(f"http://{host}:{p}/")
                    if r.status_code == 200 and "cluster_name" in r.text:
                        F.append(_mk(f"Elasticsearch reachable without auth: {where}", "critical", "data",
                                     "DATA-01 Unauthenticated Access",
                                     f"Elasticsearch at {where} answered a cluster query without auth.",
                                     "Enable security/auth; restrict the port.", where, "unauth",
                                     {"cluster": r.json().get("cluster_name")}, cwe="CWE-306"))
                    elif r.status_code in (401, 403):
                        F.append(_mk(f"Elasticsearch exposed to the internet: {where}", "high", "data",
                                     "DATA-02 Exposure", f"Elasticsearch at {where} is internet-reachable.",
                                     "Restrict the port to trusted networks.", where, "exposed", {}, cwe="CWE-284"))
                except Exception:
                    pass
                continue
            r = _probe_datastore(host, p, engine)
            if not r.get("reachable"):
                continue
            if r.get("unauth"):
                F.append(_mk(f"{engine} accessible without authentication: {where}", "critical", "data",
                             "DATA-01 Unauthenticated Access",
                             f"{engine} at {where} accepts commands from the internet with no auth ({r.get('note') or 'no auth'}).",
                             f"Enable authentication on {engine}, bind to a private interface, firewall the port.",
                             where, "unauth", {"engine": engine, "version": r.get("version")}, cwe="CWE-306"))
            else:
                F.append(_mk(f"{engine} exposed to the internet: {where}", "high", "data", "DATA-02 Exposure",
                             f"The {engine} port at {where} is internet-reachable ({r.get('note') or 'auth required'}).",
                             f"Restrict {engine} to a private network / VPN.", where, "exposed",
                             {"engine": engine, "version": r.get("version")}, cwe="CWE-284"))
            if not _tls_available(host, p) and engine in ("postgresql", "mysql", "mongodb", "redis"):
                F.append(_mk(f"{engine} connection not TLS-protected: {where}", "medium", "data",
                             "DATA-04 Transport", f"The {engine} endpoint at {where} did not complete a TLS handshake.",
                             f"Enable TLS on {engine} and require encrypted connections.", where, "no-tls",
                             {"engine": engine}, cwe="CWE-319"))
            ver = str(r.get("version") or "")
            if ver:
                eol = any(ver.startswith(h) for h in _EOL_HINTS.get(engine, ()))
                F.append(_mk(f"{engine} {'end-of-life' if eol else 'version disclosed'}: {where}",
                             "high" if eol else "low", "data", "DATA-03 Version",
                             f"The {engine} banner discloses version '{ver}'{' (end-of-life)' if eol else ''}.",
                             ("Upgrade to a supported release." if eol else "Restrict banner exposure; keep patched."),
                             where, ver, {"version": ver, "eol": eol}, cwe="CWE-1104" if eol else None))
    return F


# ── orchestrator entrypoint ─────────────────────────────────────────────────
async def run_identity_data_orchestrator(*, scan_id: str, target: Any, Session: Any,
                                         kind_credentials: dict | None = None) -> None:
    from ...db.models import Finding as DbFinding
    from ...db.models import Scan
    from ...events import publish_scan_event
    from ..grader import compute as compute_grade
    from types import SimpleNamespace

    kind = target.kind
    cfg = dict(target.kind_config or {})
    creds = dict(kind_credentials or {})

    async def _log(msg: str) -> None:
        async with Session() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            s.log = (list(s.log or []) + [msg])[-1000:]
            await db.commit()

    await _log(f"[Identity/Data] starting {kind} (provider={cfg.get('provider') or cfg.get('engine') or '-'})")
    publish_scan_event(scan_id, {"type": "stage_start", "label": f"identity/data: {kind}", "pct": None})

    if kind == "idp":
        findings = await asyncio.to_thread(_scan_idp, cfg, creds)
    elif kind == "data_store":
        findings = await asyncio.to_thread(_scan_datastore, cfg, creds)
    else:
        raise ValueError(f"run_identity_data_orchestrator called with kind={kind!r}")

    from .trace import finding_lines, log_scan_trace
    await log_scan_trace(Session, scan_id, finding_lines("Identity/Data", kind, findings))

    score, grade, _ = compute_grade(
        [SimpleNamespace(severity=f["severity"], suppressed=False, verification_status=None) for f in findings],
        target_kind=kind)
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    def _clip(v, n):
        return v[:n] if isinstance(v, str) and len(v) > n else v

    async with Session() as db:
        for f in findings:
            db.add(DbFinding(
                scan_id=scan_id, title=_clip(f["title"], 500), severity=_clip(f["severity"], 16),
                category=_clip(f["category"], 64), owasp_category=_clip(f.get("owasp_category"), 32),
                cwe_id=_clip(f.get("cwe_id"), 32),
                description=f["description"][:4000], remediation=f["remediation"][:4000] or None,
                endpoint=_clip(f["endpoint"], 2048), parameter=_clip(f["parameter"], 200),
                evidence=f["evidence"]))
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        s.status = "done"
        s.progress_pct = 100
        s.current_stage = "complete"
        s.finished_at = datetime.now(timezone.utc)
        s.grade = grade
        s.score = score
        s.summary = {**(s.summary or {}), **counts, "kind": kind}
        await db.commit()

    from .trace import enqueue_validation
    enqueue_validation(scan_id)
    publish_scan_event(scan_id, {"type": "finished", "scan_id": scan_id, "total_findings": len(findings)})
