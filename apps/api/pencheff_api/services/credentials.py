import base64
import json
import os

from cryptography.fernet import Fernet

from ..config import get_settings

_settings = get_settings()


def _fernet() -> Fernet:
    key = _settings.fernet_key or os.environ.get("FERNET_KEY", "")
    if not key:
        # Dev fallback — NOT for production. Derive a stable key from jwt_secret.
        digest = _settings.jwt_secret.encode("utf-8")[:32].ljust(32, b"0")
        key = base64.urlsafe_b64encode(digest).decode()
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_credentials(creds: dict | None) -> bytes | None:
    if not creds:
        return None
    payload = json.dumps({k: v for k, v in creds.items() if v}, separators=(",", ":")).encode()
    return _fernet().encrypt(payload)


def decrypt_credentials(blob: bytes | None) -> dict | None:
    if not blob:
        return None
    try:
        return json.loads(_fernet().decrypt(blob).decode())
    except Exception:
        return None
