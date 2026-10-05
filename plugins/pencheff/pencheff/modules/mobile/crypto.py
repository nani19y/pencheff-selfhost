"""Mobile crypto static analysis — DES/MD5/ECB/hardcoded-IVs in jadx-decompiled .java."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule
from pencheff.modules.mobile import jadx

CRYPTO_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str, str, str]] = [
    (
        "DES cipher",
        re.compile(r"Cipher\.getInstance\(\s*\"DES(?:/[^\"]*)?\""),
        Severity.HIGH,
        "DES is a 56-bit block cipher and is considered broken — exhaustive key search is feasible. Any data encrypted with DES is effectively in cleartext.",
        "Replace DES with AES-256-GCM. For Android, use the Jetpack Security library or Cipher.getInstance(\"AES/GCM/NoPadding\").",
        "CWE-327",
    ),
    (
        "3DES cipher",
        re.compile(r"Cipher\.getInstance\(\s*\"DESede(?:/[^\"]*)?\""),
        Severity.MEDIUM,
        "Triple DES (DESede) is deprecated by NIST (SP 800-131A). Block size of 64 bits makes it vulnerable to birthday attacks (Sweet32) for long-lived keys.",
        "Replace 3DES with AES-256-GCM.",
        "CWE-327",
    ),
    (
        "RC4 cipher",
        re.compile(r"Cipher\.getInstance\(\s*\"(RC4|ARC4|ARCFOUR)"),
        Severity.HIGH,
        "RC4 has known biases and is prohibited by RFC 7465. Practical attacks recover plaintext from ciphertext-only captures.",
        "Replace RC4 with AES-GCM.",
        "CWE-327",
    ),
    (
        "ECB mode",
        re.compile(r"Cipher\.getInstance\(\s*\"[A-Z0-9]+/ECB"),
        Severity.HIGH,
        "ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking plaintext structure (the famous ECB Penguin). It also provides no integrity.",
        "Use authenticated encryption: AES/GCM/NoPadding with a fresh 12-byte IV per message.",
        "CWE-327",
    ),
    (
        "MD5 hash",
        re.compile(r"MessageDigest\.getInstance\(\s*\"MD5\""),
        Severity.MEDIUM,
        "MD5 is cryptographically broken — collisions can be found in seconds. Unsafe for password hashing, signatures, or HMAC.",
        "Use SHA-256 (or higher) for hashing. For password storage, use Argon2id, bcrypt, or scrypt with a per-user salt.",
        "CWE-327",
    ),
    (
        "SHA-1 hash",
        re.compile(r"MessageDigest\.getInstance\(\s*\"SHA-?1\""),
        Severity.LOW,
        "SHA-1 is deprecated for signatures (SHAttered, 2017). Still acceptable as a checksum but not for security-critical uses.",
        "Use SHA-256 or SHA-3 for any security-relevant hashing.",
        "CWE-328",
    ),
    (
        "Insecure RNG (java.util.Random)",
        re.compile(r"\bnew\s+(?:java\.util\.)?Random\s*\("),
        Severity.MEDIUM,
        "java.util.Random is a linear-congruential generator — its output is predictable from a single observation. Unsafe for tokens, IVs, salts, or any security-relevant value.",
        "Use java.security.SecureRandom for any security-relevant randomness.",
        "CWE-338",
    ),
    (
        "Hardcoded IvParameterSpec",
        re.compile(r"new\s+IvParameterSpec\s*\(\s*(?:new\s+byte\[\]\s*\{[^}]*\}|\"[^\"]+\"\.getBytes\(\))"),
        Severity.HIGH,
        "An IV (initialization vector) is hardcoded as a byte literal or constant string. Reusing an IV across encryptions defeats the security of CBC/GCM and can leak plaintext or forge ciphertexts.",
        "Generate a fresh, cryptographically random IV per encryption (12 bytes for GCM, 16 bytes for CBC). Prepend it to the ciphertext for the receiver to use during decryption.",
        "CWE-329",
    ),
    (
        "Hardcoded SecretKeySpec",
        re.compile(r"new\s+SecretKeySpec\s*\(\s*(?:new\s+byte\[\]\s*\{[^}]*\}|\"[^\"]+\"\.getBytes\(\))"),
        Severity.HIGH,
        "A symmetric key is hardcoded as a byte literal or string. Anyone with the APK can extract this key and decrypt all data the app encrypts (or forge ciphertexts).",
        "Derive keys from user input via PBKDF2/Argon2 with a per-install salt, or store in the Android Keystore (which the app cannot exfiltrate). Rotate the leaked key.",
        "CWE-321",
    ),
]

MAX_FILES_SCANNED = 5000
MAX_HITS_PER_KIND = 25
MAX_BYTES_PER_FILE = 5_000_000  # 5 MB cap — bounds memory on adversarial inputs


class MobileCryptoModule(BaseTestModule):
    """Detect insecure cryptographic primitives and key/IV reuse in decompiled Java."""

    name = "mobile_crypto"
    category = "mobile_crypto"
    owasp_categories = ["M10"]
    description = "Insecure crypto detection: DES/RC4/ECB, MD5/SHA-1, hardcoded keys/IVs, insecure RNG"

    def get_techniques(self) -> list[str]:
        return [
            "weak_cipher_detection",
            "ecb_mode_detection",
            "broken_hash_detection",
            "hardcoded_key_iv_detection",
            "insecure_rng_detection",
        ]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        cfg = config or {}
        apk_path = cfg.get("apk_path")
        decomp_dir = cfg.get("jadx_dir")

        if not apk_path and not decomp_dir:
            return []

        if not decomp_dir:
            decomp = await jadx.recover(apk_path)
            if "error" in decomp:
                return []
            decomp_dir = decomp.get("output_dir")
            if not decomp_dir:
                return []

        root = Path(decomp_dir)
        findings: list[Finding] = []
        hits_by_kind: dict[str, int] = {}
        files_scanned = 0

        for path in root.rglob("*.java"):
            if files_scanned >= MAX_FILES_SCANNED:
                break
            files_scanned += 1
            try:
                with path.open("rb") as f:
                    raw = f.read(MAX_BYTES_PER_FILE)
                text = raw.decode("utf-8", errors="replace")
            except OSError:
                continue

            for label, pattern, severity, desc, fix, cwe in CRYPTO_PATTERNS:
                if hits_by_kind.get(label, 0) >= MAX_HITS_PER_KIND:
                    continue
                for m in pattern.finditer(text):
                    hits_by_kind[label] = hits_by_kind.get(label, 0) + 1
                    line_no = text.count("\n", 0, m.start()) + 1
                    snippet = self._line_snippet(text, m.start())
                    findings.append(Finding(
                        title=f"Insecure crypto: {label}",
                        severity=severity,
                        category="mobile_crypto",
                        owasp_category="M10",
                        description=desc,
                        remediation=fix,
                        endpoint=str(path.relative_to(root)),
                        parameter=f"line:{line_no}",
                        cwe_id=cwe,
                        cvss_score=7.4 if severity == Severity.HIGH else (5.3 if severity == Severity.MEDIUM else 3.7),
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" if severity == Severity.HIGH else "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        evidence=[Evidence(
                            request_method="STATIC",
                            request_url=f"{path.relative_to(root)}:{line_no}",
                            description=snippet,
                        )],
                        references=["https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography"],
                    ))
                    if hits_by_kind[label] >= MAX_HITS_PER_KIND:
                        break

        return findings

    @staticmethod
    def _line_snippet(text: str, pos: int, width: int = 120) -> str:
        line_start = text.rfind("\n", 0, pos) + 1
        line_end = text.find("\n", pos)
        if line_end == -1:
            line_end = len(text)
        line = text[line_start:line_end].strip()
        if len(line) > width:
            line = line[:width] + "..."
        return line
