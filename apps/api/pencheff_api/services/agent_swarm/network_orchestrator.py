"""Network & Host Security orchestrator — provider-aware TLS/SSL, DNS, Email, VPN.

Read-only posture scans for four target kinds. Each does deep, provider-agnostic
("universal") checks against the endpoint/domain, plus optional provider-API
enrichment when credentials are supplied (boto3 for AWS, httpx REST for
Cloudflare/Azure/GCP/etc — no extra SDK deps). Nothing is written or exploited.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

NETWORK_KINDS = frozenset({"tls_ssl", "dns", "email_security", "vpn"})

_NET_CHECKS = {
    "tls_ssl": "certificate chain/expiry, protocol versions, weak ciphers, HSTS",
    "dns": "DNSSEC, SPF/DKIM/DMARC, zone transfer, dangling/takeover records",
    "email_security": "SPF, DKIM selectors, DMARC policy, MTA-STS, DNSSEC",
    "vpn": "exposed management, weak protocols/ciphers, IKE/SSL-VPN posture",
}


def _ev(endpoint: str, description: str, detail: dict[str, Any]) -> list[dict[str, Any]]:
    d = {k: v for k, v in detail.items() if v is not None}
    return [{"request_url": endpoint, "description": description,
             "response_body_snippet": json.dumps(d, indent=2, default=str) if d else None}]


def _mk(title, severity, category, owasp, desc, rem, endpoint, parameter, detail, cwe=None) -> dict[str, Any]:
    return {"title": title, "severity": severity, "category": category,
            "owasp_category": owasp, "cwe_id": cwe, "description": desc, "remediation": rem,
            "endpoint": endpoint, "parameter": parameter, "evidence": _ev(endpoint, desc, detail)}


def _split_hostport(entry: str, default_port: int) -> tuple[str, int]:
    entry = entry.strip().replace("https://", "").replace("http://", "").rstrip("/")
    if ":" in entry and entry.count(":") == 1:
        h, _, p = entry.partition(":")
        return h, int(p) if p.isdigit() else default_port
    return entry, default_port


# ── TLS/SSL ─────────────────────────────────────────────────────────────────
_TLS_VERSIONS = [
    ("SSLv3", ssl.TLSVersion.SSLv3, "-ssl3"), ("TLSv1.0", ssl.TLSVersion.TLSv1, "-tls1"),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "-tls1_1"), ("TLSv1.2", ssl.TLSVersion.TLSv1_2, "-tls1_2"),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, "-tls1_3"),
]
_LEGACY_TLS = {"SSLv3", "TLSv1.0", "TLSv1.1"}
_WEAK_CIPHER_CLASSES = {
    "RC4": "RC4", "3DES": "3DES:DES", "NULL": "NULL:eNULL", "EXPORT": "EXPORT",
    "anon": "aNULL", "MD5": "MD5",
}


def _run(cmd: list[str], timeout: float = 12.0, stdin: bytes = b"") -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).decode("utf-8", "ignore")
    except (subprocess.SubprocessError, OSError):
        return -1, ""


def _openssl_supports(host: str, port: int, flag: str) -> bool | None:
    """Return True/False if openssl can determine protocol support, None if it can't
    even offer that version (client-side limitation, not a server verdict)."""
    if not shutil.which("openssl"):
        return None
    rc, out = _run(["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host,
                    flag, "-cipher", "DEFAULT@SECLEVEL=0"], timeout=10, stdin=b"Q\n")
    if "no protocols available" in out or "unknown option" in out:
        return None
    return "BEGIN CERTIFICATE" in out or "Cipher    :" in out and "(NONE)" not in out


def _openssl_cipher_supported(host: str, port: int, cipher_spec: str) -> bool:
    if not shutil.which("openssl"):
        return False
    rc, out = _run(["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host,
                    "-cipher", f"{cipher_spec}@SECLEVEL=0"], timeout=8, stdin=b"Q\n")
    return "BEGIN CERTIFICATE" in out


def _cert_details(der_or_pem: bytes, is_pem: bool = False) -> dict[str, Any]:
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(der_or_pem) if is_pem else x509.load_der_x509_certificate(der_or_pem)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    try:
        sans = [n.value for n in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
    except Exception:
        sans = []
    return {
        "not_after": na,
        "issuer": cert.issuer.rfc4514_string(),
        "subject": cert.subject.rfc4514_string(),
        "self_signed": cert.issuer == cert.subject,
        "key_bits": getattr(cert.public_key(), "key_size", None),
        "sig_alg": cert.signature_algorithm_oid._name,
        "sans": [str(s) for s in sans],
    }


def _tls_cert_info(host: str, port: int) -> dict[str, Any] | None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                negotiated = ss.version()
    except (ssl.SSLError, OSError):
        return None
    info: dict[str, Any] = {"negotiated": negotiated}
    if der:
        try:
            info.update(_cert_details(der))
        except Exception:
            pass
    return info


def _cert_findings(where: str, cert: dict[str, Any], host: str | None = None) -> list[dict[str, Any]]:
    F = []
    na = cert.get("not_after")
    if na is not None:
        days = (na - datetime.now(timezone.utc)).days
        if days < 0:
            F.append(_mk(f"TLS certificate expired: {where}", "high", "tls", "TLS-02 Certificate Validity",
                         f"The certificate for {where} expired {abs(days)} day(s) ago.",
                         "Renew and deploy a valid certificate.", where, "expired",
                         {"not_after": str(na), "issuer": cert.get("issuer")}, cwe="CWE-298"))
        elif days < 30:
            F.append(_mk(f"TLS certificate expiring soon: {where}", "medium", "tls", "TLS-02 Certificate Validity",
                         f"The certificate for {where} expires in {days} day(s).",
                         "Renew before expiry; automate renewal.", where, f"{days}d", {"not_after": str(na)}))
    if cert.get("self_signed"):
        F.append(_mk(f"Self-signed TLS certificate: {where}", "medium", "tls", "TLS-02 Certificate Validity",
                     f"The certificate for {where} is self-signed.", "Use a certificate from a trusted CA.",
                     where, "self-signed", {"issuer": cert.get("issuer")}, cwe="CWE-295"))
    kb = cert.get("key_bits")
    if isinstance(kb, int) and kb < 2048:
        F.append(_mk(f"Weak TLS certificate key ({kb}-bit): {where}", "high", "tls", "TLS-03 Key Strength",
                     f"The certificate for {where} uses a {kb}-bit key.",
                     "Reissue with a >=2048-bit RSA or ECDSA P-256+ key.", where, f"{kb}-bit",
                     {"key_bits": kb}, cwe="CWE-326"))
    sig = str(cert.get("sig_alg") or "").lower()
    if "sha1" in sig or "md5" in sig:
        F.append(_mk(f"Weak certificate signature algorithm: {where}", "high", "tls", "TLS-03 Key Strength",
                     f"The certificate for {where} is signed with {cert.get('sig_alg')} (deprecated/collidable).",
                     "Reissue with SHA-256+ signatures.", where, str(cert.get("sig_alg")),
                     {"sig_alg": cert.get("sig_alg")}, cwe="CWE-328"))
    if host and cert.get("sans") is not None:
        sans = [s.lower() for s in cert.get("sans", [])]
        matched = any(s == host.lower() or (s.startswith("*.") and host.lower().endswith(s[1:])) for s in sans)
        if sans and not matched:
            F.append(_mk(f"Certificate hostname mismatch: {where}", "high", "tls", "TLS-02 Certificate Validity",
                         f"The certificate for {where} does not cover {host} (SANs: {', '.join(sans[:8])}).",
                         "Issue a certificate whose SAN list includes the served hostname.", where, "san-mismatch",
                         {"host": host, "sans": cert.get("sans")}, cwe="CWE-297"))
    return F


def _scan_tls_endpoint(cfg: dict[str, Any], creds: dict[str, Any]) -> list[dict[str, Any]]:
    import httpx
    F: list[dict[str, Any]] = []
    for entry in cfg.get("hosts") or []:
        host, port = _split_hostport(str(entry), 443)
        where = f"{host}:{port}"
        cert = _tls_cert_info(host, port)
        # protocol enumeration (stdlib for 1.2/1.3, openssl best-effort for legacy)
        supported: list[str] = []
        for name, ver, flag in _TLS_VERSIONS:
            ok = None
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = ctx.maximum_version = ver
                with socket.create_connection((host, port), timeout=5) as s:
                    with ctx.wrap_socket(s, server_hostname=host):
                        ok = True
            except ValueError:
                ok = _openssl_supports(host, port, flag)  # client can't offer → ask openssl
            except (ssl.SSLError, OSError):
                ok = False
            if ok:
                supported.append(name)
        if not supported and cert is None:
            F.append(_mk(f"TLS endpoint unreachable: {where}", "info", "tls", "TLS-00 Reachability",
                         f"No TLS handshake completed against {where}.", "Confirm host/port + TLS service.",
                         where, "tls", {"host": host, "port": port}))
            continue
        if cfg.get("check_protocols", True):
            legacy = [v for v in supported if v in _LEGACY_TLS]
            if legacy:
                F.append(_mk(f"Legacy TLS/SSL protocol enabled: {where}", "high", "tls", "TLS-01 Protocol Hygiene",
                             f"{where} accepts deprecated protocol(s): {', '.join(legacy)}.",
                             "Disable SSLv3/TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3).", where, ", ".join(legacy),
                             {"supported_protocols": supported}, cwe="CWE-326"))
            if supported and "TLSv1.3" not in supported:
                F.append(_mk(f"TLS 1.3 not supported: {where}", "low", "tls", "TLS-01 Protocol Hygiene",
                             f"{where} does not offer TLS 1.3.", "Enable TLS 1.3.", where, "no-tls1.3",
                             {"supported_protocols": supported}))
        if cfg.get("check_ciphers", True) and shutil.which("openssl"):
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
                oks = list(ex.map(lambda spec: _openssl_cipher_supported(host, port, spec),
                                  _WEAK_CIPHER_CLASSES.values()))
            weak = [n for n, ok in zip(_WEAK_CIPHER_CLASSES, oks) if ok]
            if weak:
                sev = "high" if any(w in ("RC4", "NULL", "EXPORT", "anon") for w in weak) else "medium"
                F.append(_mk(f"Weak TLS cipher suites enabled: {where}", sev, "tls", "TLS-04 Cipher Strength",
                             f"{where} negotiates weak cipher class(es): {', '.join(weak)}.",
                             "Disable RC4/3DES/NULL/EXPORT/anon/MD5 ciphers; prefer AEAD (AES-GCM/CHACHA20).",
                             where, ", ".join(weak), {"weak_ciphers": weak}, cwe="CWE-327"))
        if cfg.get("check_certificate", True) and cert:
            F.extend(_cert_findings(where, cert, host))
        if cfg.get("check_hardening", True):
            try:
                with httpx.Client(timeout=6.0, verify=False) as c:  # noqa: S501 — posture probe only
                    r = c.get(f"https://{host}:{port}/")
                if "strict-transport-security" not in {k.lower() for k in r.headers}:
                    F.append(_mk(f"HSTS not enabled: {where}", "medium", "tls", "TLS-05 Hardening",
                                 f"{where} does not send a Strict-Transport-Security header.",
                                 "Send HSTS with a long max-age (>=15552000) and includeSubDomains.",
                                 where, "no-hsts", {}, cwe="CWE-319"))
            except Exception:
                pass
            rc, out = _run(["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-status"],
                           timeout=8, stdin=b"Q\n") if shutil.which("openssl") else (-1, "")
            if rc == 0 and "OCSP Response Status: successful" not in out and "OCSP response:" in out:
                F.append(_mk(f"OCSP stapling not enabled: {where}", "low", "tls", "TLS-05 Hardening",
                             f"{where} does not staple an OCSP response.", "Enable OCSP stapling.",
                             where, "no-ocsp", {}))
        if cfg.get("run_ssl_labs"):
            F.extend(_ssl_labs(host))
    return F


def _ssl_labs(host: str) -> list[dict[str, Any]]:
    import time
    import httpx
    try:
        with httpx.Client(timeout=20.0) as c:
            c.get("https://api.ssllabs.com/api/v3/analyze",
                  params={"host": host, "startNew": "on", "all": "done"})
            deadline = time.monotonic() + 120
            data = {}
            while time.monotonic() < deadline:
                r = c.get("https://api.ssllabs.com/api/v3/analyze", params={"host": host})
                data = r.json()
                if data.get("status") in ("READY", "ERROR"):
                    break
                time.sleep(10)
    except Exception:
        return []
    if data.get("status") != "READY":
        return [_mk(f"SSL Labs analysis pending: {host}", "info", "tls", "TLS-06 External Grade",
                    "Qualys SSL Labs did not finish within the time budget.", "Re-run to fetch the grade.",
                    host, "ssllabs", {"status": data.get("status")})]
    F = []
    for ep in data.get("endpoints", []):
        grade = ep.get("grade") or ep.get("gradeTrustIgnored")
        if grade and grade[0] in ("C", "D", "E", "F", "T", "M"):
            sev = "high" if grade[0] in ("D", "E", "F", "T", "M") else "medium"
            F.append(_mk(f"Low SSL Labs grade ({grade}): {host}", sev, "tls", "TLS-06 External Grade",
                         f"Qualys SSL Labs graded {ep.get('ipAddress', host)} '{grade}'.",
                         "Address the SSL Labs findings (protocols, ciphers, cert, chain).",
                         host, grade, {"grade": grade, "ip": ep.get("ipAddress")}))
    return F


def _scan_tls(cfg: dict[str, Any], creds: dict[str, Any]) -> list[dict[str, Any]]:
    source = cfg.get("source", "endpoint")
    if source == "endpoint":
        return _scan_tls_endpoint(cfg, creds)
    if source == "upload":
        pem = cfg.get("certificate_pem")
        if not pem:
            return []
        try:
            cert = _cert_details(pem.encode() if isinstance(pem, str) else pem, is_pem=True)
        except Exception as exc:
            return [_mk("Uploaded certificate could not be parsed", "info", "tls", "TLS-00 Reachability",
                        f"The uploaded PEM failed to parse: {exc}.", "Upload a valid PEM certificate.",
                        "uploaded-cert", "parse", {})]
        return _cert_findings(cert.get("subject") or "uploaded-cert", cert)
    # provider cert sources (acm/azure_keyvault/gcp/cloudflare) — enrichment
    return _tls_provider_certs(source, cfg, creds)


def _tls_provider_certs(source: str, cfg: dict[str, Any], creds: dict[str, Any]) -> list[dict[str, Any]]:
    F: list[dict[str, Any]] = []
    if source == "acm" and cfg.get("acm_certificate_arn"):
        arn = cfg["acm_certificate_arn"]
        try:
            import boto3
            sess = boto3.Session(
                aws_access_key_id=creds.get("aws_access_key_id"),
                aws_secret_access_key=creds.get("aws_secret_access_key"),
                aws_session_token=creds.get("aws_session_token"),
                region_name=creds.get("aws_region") or arn.split(":")[3] or "us-east-1")
            acm = sess.client("acm")
            desc = acm.describe_certificate(CertificateArn=arn)["Certificate"]
            body = acm.get_certificate(CertificateArn=arn).get("Certificate")
            if body:
                cert = _cert_details(body.encode(), is_pem=True)
                F.extend(_cert_findings(desc.get("DomainName") or arn, cert))
            if desc.get("RenewalEligibility") == "INELIGIBLE" and desc.get("Type") == "AMAZON_ISSUED":
                F.append(_mk(f"ACM certificate not eligible for auto-renewal: {desc.get('DomainName')}", "medium",
                             "tls", "TLS-02 Certificate Validity",
                             "The ACM certificate cannot auto-renew (validation lapsed).",
                             "Re-validate the domain so ACM can renew automatically.",
                             arn, "renewal", {"domain": desc.get("DomainName")}))
            if not desc.get("InUseBy"):
                F.append(_mk(f"ACM certificate not in use: {desc.get('DomainName')}", "low", "tls",
                             "TLS-07 Inventory", "The ACM certificate is not attached to any resource.",
                             "Remove unused certificates.", arn, "unused", {}))
        except Exception as exc:
            F.append(_mk("ACM certificate fetch failed", "info", "tls", "TLS-00 Reachability",
                         f"Could not fetch the ACM certificate ({type(exc).__name__}). Check credentials/region.",
                         "Provide AWS credentials with acm:DescribeCertificate/GetCertificate.",
                         cfg.get("acm_certificate_arn", "acm"), "acm", {}))
    elif source == "cloudflare" and cfg.get("cloudflare_zone_id"):
        F.extend(_cloudflare_tls(cfg, creds))
    else:
        F.append(_mk(f"TLS source '{source}' needs credentials/config", "info", "tls", "TLS-00 Reachability",
                     f"The {source} cert source is configured but credentials or the reference are missing.",
                     "Supply the provider credentials + certificate reference.", source, source, {}))
    return F


def _cloudflare_tls(cfg: dict[str, Any], creds: dict[str, Any]) -> list[dict[str, Any]]:
    import httpx
    F: list[dict[str, Any]] = []
    token = creds.get("cloudflare_api_token")
    zone = cfg.get("cloudflare_zone_id")
    if not token:
        return [_mk("Cloudflare TLS check needs an API token", "info", "tls", "TLS-00 Reachability",
                    "No Cloudflare API token supplied.", "Add a Cloudflare API token credential.", zone, "cf", {})]
    try:
        with httpx.Client(timeout=12.0, headers={"Authorization": f"Bearer {token}"}) as c:
            s = c.get(f"https://api.cloudflare.com/client/v4/zones/{zone}/settings/min_tls_version").json()
            mintls = (s.get("result") or {}).get("value")
            if mintls in ("1.0", "1.1"):
                F.append(_mk(f"Cloudflare minimum TLS version is {mintls}", "high", "tls", "TLS-01 Protocol Hygiene",
                             f"The Cloudflare zone allows TLS {mintls}.", "Set minimum TLS to 1.2 (prefer 1.3).",
                             zone, f"min-tls-{mintls}", {"min_tls": mintls}, cwe="CWE-326"))
    except Exception:
        pass
    return F


# ── DNS ─────────────────────────────────────────────────────────────────────
_SUBDOMAIN_WORDS = ["www", "mail", "smtp", "webmail", "dev", "staging", "stage", "test", "api",
                    "admin", "portal", "vpn", "remote", "git", "jenkins", "ftp", "db", "internal",
                    "intranet", "backup", "old", "beta", "app", "m", "ns1", "ns2", "mx",
                    "autodiscover", "cpanel", "dashboard", "cdn", "assets", "static", "img",
                    "blog", "shop", "store", "support", "help", "docs", "status", "grafana",
                    "kibana", "prometheus", "s3", "files", "download", "login", "sso", "auth"]
# CNAME target fragments that indicate a dangling/takeoverable subdomain
_TAKEOVER_FINGERPRINTS = {
    "s3.amazonaws.com": "AWS S3", "github.io": "GitHub Pages", "herokudns.com": "Heroku",
    "azurewebsites.net": "Azure App Service", "cloudapp.net": "Azure", "trafficmanager.net": "Azure TM",
    "cloudfront.net": "CloudFront", "fastly.net": "Fastly", "ghost.io": "Ghost", "wpengine.com": "WPEngine",
    "pantheonsite.io": "Pantheon", "netlify.app": "Netlify", "readthedocs.io": "ReadTheDocs",
    "surge.sh": "Surge", "bitbucket.io": "Bitbucket", "zendesk.com": "Zendesk", "unbouncepages.com": "Unbounce",
}


def _scan_dns(cfg: dict[str, Any], creds: dict[str, Any]) -> list[dict[str, Any]]:
    import dns.resolver
    import dns.query
    import dns.zone
    F: list[dict[str, Any]] = []
    domain = str(cfg.get("domain") or "").strip().rstrip(".")
    if not domain:
        return F
    res = dns.resolver.Resolver()
    res.lifetime = res.timeout = 3.0

    def q(name, rtype):
        try:
            return [r.to_text() for r in res.resolve(name, rtype)]
        except Exception:
            return []

    ns = q(domain, "NS")
    records = {rt: q(domain, rt) for rt in ("A", "AAAA", "MX", "TXT", "SOA", "NS", "CAA")}

    if cfg.get("zone_transfer", True):
        for nsrv in ns:
            nsrv = nsrv.rstrip(".")
            try:
                nsip = res.resolve(nsrv, "A")[0].to_text()
                z = dns.zone.from_xfr(dns.query.xfr(nsip, domain, timeout=5.0))
                names = [str(n) for n in z.nodes.keys()]
                F.append(_mk(f"DNS zone transfer (AXFR) allowed: {domain} via {nsrv}", "high", "dns",
                             "DNS-01 Zone Transfer",
                             f"{nsrv} answered an AXFR for {domain}, exposing the full zone ({len(names)} records).",
                             "Restrict AXFR to authorized secondary nameservers only.", domain, nsrv,
                             {"nameserver": nsrv, "records_exposed": len(names), "sample": names[:20]}, cwe="CWE-200"))
            except Exception:
                continue

    if cfg.get("check_caa", True) and not records.get("CAA"):
        F.append(_mk(f"No CAA record: {domain}", "low", "dns", "DNS-04 CA Authorization",
                     f"{domain} has no CAA record, so any CA may issue certificates for it.",
                     "Publish a CAA record naming your authorized CA(s).", domain, "no-caa", {}))

    if cfg.get("subdomain_enum", True):
        import concurrent.futures

        def _probe_sub(w):
            sub = f"{w}.{domain}"
            return sub, (q(sub, "A") or q(sub, "AAAA")), q(sub, "CNAME")

        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
            for sub, a, cname in ex.map(_probe_sub, _SUBDOMAIN_WORDS):
                if not (a or cname):
                    continue
                found.append(sub)
                if cfg.get("check_takeover", True) and cname:
                    tgt = cname[0].rstrip(".").lower()
                    fp = next((svc for frag, svc in _TAKEOVER_FINGERPRINTS.items() if frag in tgt), None)
                    if fp and not a:  # CNAME to a known service that doesn't resolve → dangling
                        F.append(_mk(f"Possible subdomain takeover: {sub}", "high", "dns", "DNS-05 Subdomain Takeover",
                                     f"{sub} is a dangling CNAME to {tgt} ({fp}) that does not resolve — takeoverable.",
                                     f"Remove the dangling CNAME or reclaim the {fp} resource.", sub, fp,
                                     {"cname": tgt, "service": fp}, cwe="CWE-350"))
        if found:
            F.append(_mk(f"Subdomains discovered: {domain}", "info", "dns", "DNS-02 Attack Surface",
                         f"{len(found)} subdomain(s) resolved via wordlist enumeration.",
                         "Review exposed subdomains; retire unused ones; watch for dangling records.",
                         domain, f"{len(found)} subdomains", {"subdomains": found}))

    if cfg.get("check_dnssec", True) and not q(domain, "DNSKEY"):
        F.append(_mk(f"DNSSEC not enabled: {domain}", "low", "dns", "DNS-03 Integrity",
                     f"No DNSKEY for {domain}; responses aren't cryptographically signed.",
                     "Enable DNSSEC at the registrar/DNS provider.", domain, "no-dnssec", {"records": records}))

    # provider enrichment — enumerate the full authoritative zone via the API
    if cfg.get("provider", "generic") != "generic" and creds:
        F.extend(_dns_provider(cfg, creds, domain))
    return F


def _dns_provider(cfg: dict[str, Any], creds: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    prov = cfg.get("provider")
    try:
        if prov == "route53" and creds.get("aws_access_key_id"):
            import boto3
            sess = boto3.Session(aws_access_key_id=creds.get("aws_access_key_id"),
                                 aws_secret_access_key=creds.get("aws_secret_access_key"),
                                 aws_session_token=creds.get("aws_session_token"))
            r53 = sess.client("route53")
            zid = cfg.get("hosted_zone_id")
            if zid:
                rrsets = r53.list_resource_record_sets(HostedZoneId=zid).get("ResourceRecordSets", [])
                dnssec = r53.get_dnssec(HostedZoneId=zid).get("Status", {}).get("ServeSignature")
                out = []
                if dnssec != "SIGNING":
                    out.append(_mk(f"Route53 zone DNSSEC not signing: {domain}", "low", "dns", "DNS-03 Integrity",
                                   "The Route53 hosted zone is not serving DNSSEC signatures.",
                                   "Enable DNSSEC signing on the hosted zone.", domain, "route53-dnssec", {}))
                out.append(_mk(f"Route53 zone enumerated: {domain}", "info", "dns", "DNS-02 Attack Surface",
                               f"Enumerated {len(rrsets)} record sets from the Route53 hosted zone.",
                               "Review the full record set for stale/dangling entries.", domain,
                               f"{len(rrsets)} records", {"record_types": sorted({r['Type'] for r in rrsets})}))
                return out
        elif prov == "cloudflare" and creds.get("cloudflare_api_token"):
            import httpx
            zone = cfg.get("cloudflare_zone_id")
            with httpx.Client(timeout=12.0, headers={"Authorization": f"Bearer {creds['cloudflare_api_token']}"}) as c:
                recs = c.get(f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records",
                             params={"per_page": 100}).json().get("result", [])
            return [_mk(f"Cloudflare zone enumerated: {domain}", "info", "dns", "DNS-02 Attack Surface",
                        f"Enumerated {len(recs)} DNS records from Cloudflare.",
                        "Review the record set for stale/dangling entries.", domain, f"{len(recs)} records",
                        {"record_types": sorted({r.get('type') for r in recs})})]
    except Exception:
        pass
    return []


# ── Email authentication ────────────────────────────────────────────────────
def _scan_email(cfg: dict[str, Any], creds: dict[str, Any]) -> list[dict[str, Any]]:
    import dns.resolver
    import httpx
    F: list[dict[str, Any]] = []
    domain = str(cfg.get("domain") or "").strip().rstrip(".")
    if not domain:
        return F
    res = dns.resolver.Resolver()
    res.lifetime = res.timeout = 5.0

    def txt(name):
        try:
            return [r.to_text().strip('"').replace('" "', "") for r in res.resolve(name, "TXT")]
        except Exception:
            return []

    spf = next((t for t in txt(domain) if t.lower().startswith("v=spf1")), None)
    if not spf:
        F.append(_mk(f"SPF record missing: {domain}", "high", "email", "EMAIL-01 SPF",
                     f"{domain} has no SPF record — the domain is easier to spoof.",
                     "Publish an SPF TXT record ending in -all.", domain, "spf", {}, cwe="CWE-290"))
    else:
        if spf.strip().endswith("+all") or " +all" in spf:
            F.append(_mk(f"SPF policy too permissive (+all): {domain}", "high", "email", "EMAIL-01 SPF",
                         f"The SPF record for {domain} ends in +all, authorizing any host.",
                         "Change +all to -all and list only authorized senders.", domain, "+all", {"spf": spf}))
        elif spf.strip().endswith("~all"):
            F.append(_mk(f"SPF uses soft-fail (~all): {domain}", "low", "email", "EMAIL-01 SPF",
                         f"The SPF record for {domain} ends in ~all.", "Move to -all once senders are confirmed.",
                         domain, "~all", {"spf": spf}))
        lookups = sum(spf.lower().count(m) for m in ("include:", "a:", "mx:", "ptr:", "exists:", "redirect="))
        if lookups > 10:
            F.append(_mk(f"SPF exceeds 10 DNS lookups: {domain}", "medium", "email", "EMAIL-01 SPF",
                         f"The SPF record needs ~{lookups} DNS lookups (>10 → permerror, SPF ignored).",
                         "Flatten includes to stay under 10 lookups.", domain, f"{lookups} lookups", {"spf": spf}))

    dmarc = next((t for t in txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        F.append(_mk(f"DMARC record missing: {domain}", "high", "email", "EMAIL-02 DMARC",
                     f"{domain} has no DMARC policy.", "Publish a _dmarc TXT record with at least p=quarantine.",
                     domain, "dmarc", {}, cwe="CWE-290"))
    else:
        # Parse the ;-separated tag list; isolate the p= tag (not sp=), tolerate
        # whitespace like "p = reject" and be case-insensitive on the tag name.
        tags = {}
        for part in dmarc.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags.setdefault(k.strip().lower(), v.strip().lower())
        if tags.get("p") == "none":
            F.append(_mk(f"DMARC policy is p=none: {domain}", "medium", "email", "EMAIL-02 DMARC",
                         f"The DMARC policy for {domain} is monitor-only.", "Move to p=quarantine then p=reject.",
                         domain, "p=none", {"dmarc": dmarc}))
        if "rua" not in tags:
            F.append(_mk(f"DMARC has no aggregate reporting (rua): {domain}", "low", "email", "EMAIL-02 DMARC",
                         "DMARC has no rua= address, so you get no visibility into spoofing.",
                         "Add a rua= mailto for aggregate reports.", domain, "no-rua", {}))

    # No way to enumerate DKIM selectors via DNS, so probe a curated list. Merge
    # any caller-supplied selectors first, then dedupe (preserving order).
    selectors = list(dict.fromkeys([
        *(cfg.get("dkim_selectors") or []),
        "google", "default", "selector1", "selector2", "s1", "s2", "k1", "k2",
        "dkim", "mail", "20230601", "20161025", "smtp", "mandrill", "mxvault",
    ]))
    found = next((s for s in selectors
                  if any(("v=dkim1" in r.lower()) or ("k=" in r.lower()) or ("p=" in r.lower())
                         for r in txt(f"{s}._domainkey.{domain}"))), None)
    if not found:
        F.append(_mk(f"No DKIM record found: {domain}", "medium", "email", "EMAIL-03 DKIM",
                     f"No DKIM key at common selectors ({', '.join(selectors)}).",
                     "Publish DKIM keys and sign outbound mail.", domain, "dkim", {"selectors_tried": selectors}))

    if cfg.get("check_mta_sts", True):
        if not txt(f"_mta-sts.{domain}"):
            F.append(_mk(f"MTA-STS not configured: {domain}", "low", "email", "EMAIL-04 Transport",
                         f"{domain} has no MTA-STS policy — inbound SMTP can be downgraded/MITM'd.",
                         "Publish an _mta-sts TXT record + policy at mta-sts.<domain>.", domain, "mta-sts", {}))
    if cfg.get("check_tls_rpt", True) and not txt(f"_smtp._tls.{domain}"):
        F.append(_mk(f"SMTP TLS-RPT not configured: {domain}", "low", "email", "EMAIL-04 Transport",
                     f"{domain} has no TLS-RPT record, so TLS delivery failures go unreported.",
                     "Publish a _smtp._tls TXT record with a rua=.", domain, "tls-rpt", {}))
    if cfg.get("check_bimi", True) and not txt(f"default._bimi.{domain}"):
        F.append(_mk(f"BIMI not configured: {domain}", "info", "email", "EMAIL-05 Brand",
                     f"{domain} has no BIMI record (brand logo in inboxes; requires DMARC enforcement).",
                     "Optionally publish a BIMI record once DMARC is at quarantine/reject.", domain, "bimi", {}))

    # provider enrichment
    if cfg.get("provider", "generic") != "generic" and creds:
        F.extend(_email_provider(cfg, creds, domain))
    return F


def _email_provider(cfg: dict[str, Any], creds: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    prov = cfg.get("provider")
    try:
        if prov == "ses" and creds.get("aws_access_key_id"):
            import boto3
            sess = boto3.Session(aws_access_key_id=creds.get("aws_access_key_id"),
                                 aws_secret_access_key=creds.get("aws_secret_access_key"),
                                 aws_session_token=creds.get("aws_session_token"),
                                 region_name=creds.get("aws_region") or "us-east-1")
            ses = sess.client("sesv2")
            try:
                ident = ses.get_email_identity(EmailIdentity=domain)
            except Exception:
                return [_mk(f"SES identity not found: {domain}", "medium", "email", "EMAIL-06 Provider",
                            f"{domain} is not a verified SES identity in this account/region.",
                            "Verify the domain in SES + enable DKIM signing.", domain, "ses-unverified", {})]
            out = []
            dkim = ident.get("DkimAttributes", {})
            if dkim.get("Status") != "SUCCESS" or not dkim.get("SigningEnabled"):
                out.append(_mk(f"SES DKIM not fully enabled: {domain}", "medium", "email", "EMAIL-06 Provider",
                               f"SES DKIM status for {domain} is {dkim.get('Status')} (signing={dkim.get('SigningEnabled')}).",
                               "Complete SES DKIM setup and enable signing.", domain, "ses-dkim", {"dkim": dkim}))
            if (ident.get("MailFromAttributes", {}).get("MailFromDomainStatus")) not in ("SUCCESS", None):
                out.append(_mk(f"SES custom MAIL FROM not verified: {domain}", "low", "email", "EMAIL-06 Provider",
                               "The SES custom MAIL FROM domain is not verified.", "Complete MAIL FROM verification.",
                               domain, "ses-mailfrom", {}))
            return out
        elif prov == "resend" and creds.get("resend_api_key"):
            import httpx
            with httpx.Client(timeout=12.0, headers={"Authorization": f"Bearer {creds['resend_api_key']}"}) as c:
                doms = c.get("https://api.resend.com/domains").json().get("data", [])
            d = next((x for x in doms if x.get("name") == domain), None)
            if not d:
                return [_mk(f"Resend domain not found: {domain}", "medium", "email", "EMAIL-06 Provider",
                            f"{domain} is not configured in Resend.", "Add + verify the domain in Resend.",
                            domain, "resend", {})]
            if d.get("status") != "verified":
                return [_mk(f"Resend domain not verified: {domain}", "medium", "email", "EMAIL-06 Provider",
                            f"Resend domain status is '{d.get('status')}'.", "Complete Resend DNS verification.",
                            domain, "resend-unverified", {"status": d.get("status")})]
    except Exception:
        pass
    return []


# ── VPN / remote access ─────────────────────────────────────────────────────
_REMOTE_PORTS = {
    22: ("SSH", "high", "tcp"), 23: ("Telnet", "critical", "tcp"), 3389: ("RDP", "high", "tcp"),
    5900: ("VNC", "high", "tcp"), 5985: ("WinRM", "high", "tcp"), 5986: ("WinRM-TLS", "high", "tcp"),
    1194: ("OpenVPN", "medium", "tcp"), 1723: ("PPTP-VPN", "high", "tcp"), 8443: ("SSL-VPN", "medium", "tcp"),
    443: ("HTTPS/SSL-VPN", "low", "tcp"), 10443: ("SSL-VPN-Alt", "medium", "tcp"), 4433: ("SSL-VPN-Alt", "medium", "tcp"),
}
# vpn_type → the ports worth probing
_VPN_TYPE_PORTS = {
    "openvpn": [1194, 443], "wireguard": [51820], "ipsec": [500, 4500, 1701],
    "ssl_vpn": [443, 8443, 10443, 4433], "pptp": [1723], "remote_access": [22, 23, 3389, 5900, 5985, 5986],
}
_SSLVPN_PRODUCTS = {"fortinet": "FortiGate SSL-VPN", "sslvpn": "SSL-VPN", "pulse": "Pulse Secure",
                    "global protect": "Palo Alto GlobalProtect", "cisco": "Cisco AnyConnect",
                    "citrix": "Citrix Gateway", "sonicwall": "SonicWall"}


async def _scan_vpn(cfg: dict[str, Any], creds: dict[str, Any]) -> list[dict[str, Any]]:
    from pencheff.core.netmap import scan_targets
    import httpx
    F: list[dict[str, Any]] = []
    hosts = [h for h in (cfg.get("hosts") or []) if isinstance(h, str) and h.strip()]
    if not hosts:
        return F
    vtype = cfg.get("vpn_type", "auto")
    tcp_ports = sorted(_VPN_TYPE_PORTS.get(vtype, list(_REMOTE_PORTS.keys())))
    udp_ports = [500, 4500] if vtype in ("auto", "ipsec") else ([51820] if vtype == "wireguard" else [])
    result = await scan_targets(hosts, tcp_ports, banners=True, timeout=3.0,
                                udp_ports=udp_ports or None)
    for pr in result.open:
        label, sev, _ = _REMOTE_PORTS.get(pr.port,
            ("IKE/IPsec-VPN" if pr.port in (500, 4500) else "WireGuard" if pr.port == 51820 else pr.service or "service",
             "low" if pr.port in (500, 4500, 51820) else "medium", "tcp"))
        where = f"{pr.host}:{pr.port}"
        if pr.port == 23:
            desc, rem = f"Telnet ({where}) sends credentials in cleartext.", "Disable Telnet; use SSH."
        elif label in ("RDP", "VNC", "SSH", "WinRM", "WinRM-TLS", "PPTP-VPN"):
            desc = f"{label} on {where} is exposed to the public internet."
            rem = f"Restrict {label} to a VPN/bastion CIDR; enforce MFA."
        else:
            desc = f"A VPN/remote-access endpoint ({label}) is exposed on {where}."
            rem = "Confirm the gateway is intended to be public; enforce MFA and keep it patched."
        F.append(_mk(f"{label} exposed to the internet: {where}", sev, "vpn", "VPN-01 Remote Access Exposure",
                     desc, rem, where, label, {"host": pr.host, "port": pr.port, "service": label,
                                               "banner": pr.banner or None}, cwe="CWE-284"))
        # SSL-VPN product fingerprint (HTTP banner)
        if pr.port in (443, 8443, 10443, 4433):
            try:
                with httpx.Client(timeout=6.0, verify=False) as c:  # noqa: S501
                    r = c.get(f"https://{pr.host}:{pr.port}/", follow_redirects=True)
                body = (r.text[:4000] + " " + " ".join(r.headers.values())).lower()
                prod = next((name for frag, name in _SSLVPN_PRODUCTS.items() if frag in body), None)
                if prod:
                    F.append(_mk(f"{prod} SSL-VPN portal exposed: {where}", "high", "vpn",
                                 "VPN-02 Gateway Exposure",
                                 f"An internet-facing {prod} SSL-VPN portal was detected on {where}.",
                                 f"Restrict the {prod} portal to trusted sources; enforce MFA; keep it patched "
                                 "(SSL-VPN gateways are frequent RCE targets).", where, prod,
                                 {"product": prod}, cwe="CWE-284"))
            except Exception:
                pass
    if not result.open:
        F.append(_mk(f"No exposed VPN/remote-access services: {hosts[0]}", "info", "vpn",
                     "VPN-01 Remote Access Exposure", f"No {vtype} services found open on {', '.join(hosts)}.",
                     "No action — surface is minimal.", hosts[0], vtype, {}))
    return F


# ── orchestrator entrypoint ─────────────────────────────────────────────────
async def run_network_orchestrator(*, scan_id: str, target: Any, Session: Any,
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

    await _log(f"[Network] starting {kind} posture check (provider={cfg.get('provider') or cfg.get('source') or '-'})")
    await _log(f"[Network] probing {kind}: {_NET_CHECKS.get(kind, 'posture')}")
    publish_scan_event(scan_id, {"type": "stage_start", "label": f"network: {kind}", "pct": None})

    if kind == "tls_ssl":
        findings = await asyncio.to_thread(_scan_tls, cfg, creds)
    elif kind == "dns":
        findings = await asyncio.to_thread(_scan_dns, cfg, creds)
    elif kind == "email_security":
        findings = await asyncio.to_thread(_scan_email, cfg, creds)
    elif kind == "vpn":
        findings = await _scan_vpn(cfg, creds)
    else:
        raise ValueError(f"run_network_orchestrator called with non-network kind={kind!r}")

    from .trace import finding_lines, log_scan_trace
    await log_scan_trace(Session, scan_id, finding_lines("Network", kind, findings))

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
