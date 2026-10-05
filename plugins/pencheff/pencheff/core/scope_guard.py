"""Authorization & scope enforcement for Tier 2 playbooks.

Mirrors the source repo's ``_scope-guard.md`` block:
- Tier 2 (execution) requires explicit scope declaration before any active
  reconnaissance or exploitation.
- Tier 1 (advisory) can analyze user-supplied output without scope.
- Validation gates: target ∈ scope, no destructive ops without approval,
  callbacks within operator infrastructure, no permission bypass.
- OPSEC tagging: every action lands in the QUIET / MODERATE / LOUD taxonomy.

The scope file format (YAML or JSON):

```yaml
client: ACME Corp
type: external          # external | internal | webapp | cloud | wireless | mobile
domains:
  - acme.com
  - "*.acme.com"
ip_ranges:
  - 198.51.100.0/24
urls:
  - https://app.acme.com
cloud_accounts:
  - aws:123456789012
oast_callbacks:
  - acme.oast.fun
allow_destructive: false
authorized_by: jane@acme.com
```
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class ScopeViolation(Exception):
    """Target falls outside the declared engagement scope."""


class ScopeNotDeclared(Exception):
    """A Tier 2 action attempted without a scope file loaded."""


@dataclass
class ScopeGuard:
    client: str = ""
    engagement_type: str = "external"
    domains: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    cloud_accounts: list[str] = field(default_factory=list)
    oast_callbacks: list[str] = field(default_factory=list)
    allow_destructive: bool = False
    authorized_by: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str | Path) -> "ScopeGuard":
        p = Path(path).expanduser()
        text = p.read_text()
        if p.suffix.lower() in (".yaml", ".yml"):
            try:
                import yaml  # already a dependency
            except ImportError as e:  # pragma: no cover
                raise RuntimeError("pyyaml is required to parse YAML scope files") from e
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScopeGuard":
        return cls(
            client=data.get("client", ""),
            engagement_type=data.get("type", "external"),
            domains=list(data.get("domains", []) or []),
            ip_ranges=list(data.get("ip_ranges", []) or []),
            urls=list(data.get("urls", []) or []),
            cloud_accounts=list(data.get("cloud_accounts", []) or []),
            oast_callbacks=list(data.get("oast_callbacks", []) or []),
            allow_destructive=bool(data.get("allow_destructive", False)),
            authorized_by=data.get("authorized_by", ""),
            raw=data,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "client": self.client,
            "type": self.engagement_type,
            "domains": self.domains,
            "ip_ranges": self.ip_ranges,
            "urls": self.urls,
            "cloud_accounts": self.cloud_accounts,
            "oast_callbacks": self.oast_callbacks,
            "allow_destructive": self.allow_destructive,
            "authorized_by": self.authorized_by,
        }

    # ── validation ─────────────────────────────────────────────────
    def validate(self, target: str) -> None:
        """Raise ``ScopeViolation`` if target is not in scope."""
        if not target:
            raise ScopeViolation("empty target")
        host = _extract_host(target)
        # URL exact-prefix match
        for u in self.urls:
            if target.startswith(u):
                return
        # Domain (with glob) match
        for d in self.domains:
            if fnmatch.fnmatch(host, d):
                return
        # IP range match
        try:
            ip = ipaddress.ip_address(host)
            for r in self.ip_ranges:
                try:
                    if ip in ipaddress.ip_network(r, strict=False):
                        return
                except ValueError:
                    continue
        except ValueError:
            pass
        raise ScopeViolation(
            f"target '{target}' is not in declared scope "
            f"(client={self.client or '?'}, domains={self.domains}, ip_ranges={self.ip_ranges})"
        )

    def validate_domain(self, domain: str) -> None:
        domain = domain.lower().strip()
        for d in self.domains:
            if fnmatch.fnmatch(domain, d.lower()):
                return
        raise ScopeViolation(f"domain '{domain}' is not in declared scope")

    def validate_cloud(self, account: str) -> None:
        if account in self.cloud_accounts:
            return
        raise ScopeViolation(f"cloud account '{account}' is not in declared scope")


def _extract_host(target: str) -> str:
    target = target.strip()
    if "://" in target:
        return urlparse(target).hostname or target
    # bare host[:port]
    return re.sub(r":\d+$", "", target)


# Module-level current scope (set by CLI / orchestrator entry points).
_CURRENT: ScopeGuard | None = None


def set_scope(guard: ScopeGuard | None) -> None:
    global _CURRENT
    _CURRENT = guard


def current_scope() -> ScopeGuard | None:
    return _CURRENT


def require_scope() -> ScopeGuard:
    g = current_scope()
    if g is None:
        raise ScopeNotDeclared(
            "Tier 2 action requires --scope FILE. "
            "See plugins/pencheff/docs/ENGAGEMENT-LIFECYCLE.md for the format."
        )
    return g
