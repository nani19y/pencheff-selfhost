"""Pencheff authorization vocabulary and Keycloak role/group mappings.

Authentication is delegated to the configured OIDC identity provider.
Authorization is evaluated locally from signed Keycloak access-token claims.

The catalog is intentionally explicit: administrators can inspect exactly
which permission is required by an API capability before assigning a role to
an individual user or group in Keycloak.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PermissionSpec:
    name: str
    description: str
    category: str
    risk: str = "normal"


PERMISSION_CATALOG: tuple[PermissionSpec, ...] = (
    PermissionSpec("targets:read", "View registered targets and target configuration.", "targets"),
    PermissionSpec("targets:write", "Register, edit, and delete targets.", "targets", "high"),
    PermissionSpec("scans:read", "View scans and scan status.", "scans"),
    PermissionSpec("scans:write", "Start and manage security scans.", "scans", "high"),
    PermissionSpec("findings:read", "View security findings.", "findings"),
    PermissionSpec("reports:read", "View and download security reports.", "reports"),
    PermissionSpec("fix_proposals:read", "View remediation proposals.", "remediation"),
    PermissionSpec("fix_proposals:write", "Generate or manage remediation proposals.", "remediation", "high"),
    PermissionSpec("remediation:approve", "Approve an AI-generated remediation for execution.", "remediation", "critical"),
    PermissionSpec("remediation:execute", "Execute an approved remediation.", "remediation", "critical"),
    PermissionSpec("ai:read_data", "Allow an AI agent to read explicitly permitted Pencheff data.", "ai", "high"),
    PermissionSpec("ai:register_target", "Allow an AI agent to register targets on behalf of a user.", "ai", "critical"),
    PermissionSpec("ai:run_scan", "Allow an AI agent to start scans.", "ai", "critical"),
    PermissionSpec("ai:report", "Allow an AI agent to generate/read findings and reports.", "ai"),
    PermissionSpec("ai:propose_remediation", "Allow an AI agent to create remediation proposals, never execute them.", "ai", "high"),
    PermissionSpec("org:manage_members", "Manage organization membership.", "administration", "critical"),
    PermissionSpec("org:manage_permissions", "Assign authorization roles/groups for the organization.", "administration", "critical"),
    PermissionSpec("org:manage_settings", "Change organization security settings.", "administration", "critical"),
)

ALL_PERMISSIONS = frozenset(p.name for p in PERMISSION_CATALOG)

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "pencheff-admin": frozenset(ALL_PERMISSIONS),
    "pencheff-security-admin": frozenset({
        "targets:read", "targets:write", "scans:read", "scans:write",
        "findings:read", "reports:read", "fix_proposals:read",
        "fix_proposals:write", "remediation:approve", "remediation:execute",
        "ai:read_data", "ai:register_target", "ai:run_scan",
        "ai:report", "ai:propose_remediation",
    }),
    "pencheff-security": frozenset({
        "targets:read", "targets:write", "scans:read", "scans:write",
        "findings:read", "reports:read", "fix_proposals:read",
        "fix_proposals:write", "ai:read_data", "ai:run_scan",
        "ai:report", "ai:propose_remediation",
    }),
    "pencheff-readonly": frozenset({
        "targets:read", "scans:read", "findings:read", "reports:read",
        "fix_proposals:read", "ai:report",
    }),
    "pencheff-ai-agent": frozenset({
        "ai:read_data", "ai:register_target", "ai:run_scan",
        "ai:report", "ai:propose_remediation",
        "targets:read", "scans:read", "findings:read", "reports:read",
        "fix_proposals:read", "fix_proposals:write",
    }),
}

# Existing groups used in the user's local Keycloak lab. Groups can carry
# these roles; direct user role mappings work through the same ROLE_PERMISSIONS
# table, so both group-based and single-user authorization are supported.
GROUP_ROLE_ALIASES: dict[str, str] = {
    "pencheff-admins": "pencheff-admin",
    "pencheff-security": "pencheff-security",
    "pencheff-readonly": "pencheff-readonly",
    "pencheff-ai-agents": "pencheff-ai-agent",
}


def permissions_for_claims(claims: dict) -> set[str]:
    """Resolve effective permissions from direct roles and group claims."""
    roles: set[str] = set()
    realm_access = claims.get("realm_access") or {}
    if isinstance(realm_access, dict):
        roles.update(str(r) for r in (realm_access.get("roles") or []))

    resource_access = claims.get("resource_access") or {}
    if isinstance(resource_access, dict):
        for resource in resource_access.values():
            if isinstance(resource, dict):
                roles.update(str(r) for r in (resource.get("roles") or []))

    groups = claims.get("groups") or []
    for group in groups:
        group_name = str(group).strip("/").split("/")[-1]
        mapped = GROUP_ROLE_ALIASES.get(group_name)
        if mapped:
            roles.add(mapped)

    permissions: set[str] = set()
    for role in roles:
        if role in ROLE_PERMISSIONS:
            permissions.update(ROLE_PERMISSIONS[role])
    return permissions


def catalog_payload() -> list[dict]:
    return [
        {
            "permission": p.name,
            "description": p.description,
            "category": p.category,
            "risk": p.risk,
        }
        for p in PERMISSION_CATALOG
    ]
