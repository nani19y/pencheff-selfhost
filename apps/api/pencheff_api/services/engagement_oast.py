"""Per-engagement OAST provisioning.

When ``OAST_BASE_DOMAIN`` is set in the environment AND ``docker`` is on
the operator's PATH, ``provision_oast`` allocates a dedicated
``interactsh-server`` container per engagement, with its own subdomain and
auth token. Otherwise the engagement falls back to the shared (oast.fun)
backend that ``OASTManager`` already supports.

This service is intentionally tolerant: a failed Docker call must not
prevent engagement creation, only downgrade the OAST mode to ``shared``.
"""
from __future__ import annotations

import os
import secrets
import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from ..db.models import Engagement


@dataclass
class OASTProvision:
    mode: str           # "per_engagement" | "shared"
    domain: str | None
    token: str | None
    container_id: str | None
    note: str | None = None


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _base_domain() -> str | None:
    return (os.environ.get("OAST_BASE_DOMAIN") or "").strip() or None


def _slug_to_subdomain(slug: str) -> str:
    return "".join(c for c in slug.lower() if c.isalnum() or c == "-")[:48] or "engagement"


def provision_oast(engagement: "Engagement") -> OASTProvision:
    base = _base_domain()
    if not base or not _docker_available():
        return OASTProvision(
            mode="shared",
            domain=None,
            token=None,
            container_id=None,
            note=(
                "Falling back to shared interactsh.com. Set OAST_BASE_DOMAIN "
                "and install Docker to provision a per-engagement server."
            ),
        )

    sub = _slug_to_subdomain(engagement.slug)
    domain = f"{sub}.{base}"
    token = secrets.token_urlsafe(24)

    name = f"pencheff-oast-{sub}"
    cmd = [
        "docker", "run", "-d", "--name", name,
        "--restart", "unless-stopped",
        "-p", "53:53/udp", "-p", "53:53/tcp",
        "-p", "80:80", "-p", "443:443",
        "projectdiscovery/interactsh-server:latest",
        "-domain", domain,
        "-auth", token,
    ]
    try:
        cid = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=20).decode().strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return OASTProvision(
            mode="shared",
            domain=None,
            token=None,
            container_id=None,
            note=f"docker run failed, falling back to shared OAST: {exc}",
        )

    return OASTProvision(
        mode="per_engagement",
        domain=domain,
        token=token,
        container_id=cid,
    )


def revoke_oast(engagement: "Engagement") -> None:
    cid = engagement.oast_container_id
    if not cid or not _docker_available():
        return
    for action in (["docker", "stop", cid], ["docker", "rm", cid]):
        try:
            subprocess.check_call(action, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        except Exception:
            pass
