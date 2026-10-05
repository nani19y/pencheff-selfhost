"""Read-only cloud posture scanners for Infrastructure & Cloud targets.

These checks operate on provider/resource metadata supplied in
``Target.kind_config.inventory``. They never require, request, or persist cloud
secret values; all evidence is redacted before returning findings.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

CLOUD_KINDS = frozenset({
    "cloud_account",
    "serverless_function",
    "cloud_storage",
    "load_balancer_cdn",
    "cloud_database",
    "secrets_manager",
})

AGENT_ROLES: dict[str, str] = {
    "CloudInventoryAgent": "Normalizes read-only provider metadata",
    "CloudIamExposureAgent": "Finds overbroad IAM and entitlement risks",
    "CloudStorageAgent": "Checks storage public access, encryption, and logging",
    "ServerlessSecurityAgent": "Checks function exposure, runtimes, and env metadata",
    "EdgeCdnSecurityAgent": "Checks load balancer and CDN TLS, WAF, and cache posture",
    "CloudDatabaseAgent": "Checks database public access, encryption, backups, and deletion protection",
    "SecretsHygieneAgent": "Checks secret metadata without reading secret values",
    "CloudAuditLoggingAgent": "Checks account-level audit logging coverage",
}

_SECRETISH_KEYS = {
    "value",
    "secret",
    "secret_value",
    "secretstring",
    "secret_string",
    "password",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "private_key",
    "plaintext",
}


def run_cloud_checks(
    *,
    kind: str,
    cfg: dict[str, Any],
    kind_credentials: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Run deterministic read-only checks for one cloud target kind.

    Args:
        kind: Target.kind wire value.
        cfg: Target.kind_config payload.
        kind_credentials: Decrypted provider credentials metadata. Presence is
            recorded in stats only; credential values are never emitted.
    """
    if kind not in CLOUD_KINDS:
        raise ValueError(f"unsupported cloud kind: {kind!r}")

    provider = str(cfg.get("provider") or "unknown")
    inventory = cfg.get("inventory") if isinstance(cfg.get("inventory"), dict) else {}
    scope = _scope_for(cfg)

    findings: list[dict[str, Any]] = []
    stats = _empty_stats(provider, scope, bool(kind_credentials), inventory)

    if kind in {"cloud_account", "serverless_function", "cloud_storage", "cloud_database", "secrets_manager"}:
        _extend(stats, findings, "CloudIamExposureAgent", _check_iam(provider, scope, inventory))

    if kind in {"cloud_account", "cloud_storage"}:
        _extend(stats, findings, "CloudStorageAgent", _check_storage(provider, scope, cfg, inventory))

    if kind in {"cloud_account", "serverless_function"}:
        _extend(stats, findings, "ServerlessSecurityAgent", _check_serverless(provider, scope, cfg, inventory))

    if kind in {"cloud_account", "load_balancer_cdn"}:
        _extend(stats, findings, "EdgeCdnSecurityAgent", _check_edge(provider, scope, cfg, inventory))

    if kind in {"cloud_account", "cloud_database"}:
        _extend(stats, findings, "CloudDatabaseAgent", _check_databases(provider, scope, cfg, inventory))

    if kind in {"cloud_account", "secrets_manager"}:
        _extend(stats, findings, "SecretsHygieneAgent", _check_secrets(provider, scope, cfg, inventory))

    if kind == "cloud_account":
        _extend(stats, findings, "CloudAuditLoggingAgent", _check_audit_logging(provider, scope, inventory))

    # AWS-native offline inventory (resources.{s3_buckets,rds,ec2,iam,...}) — the
    # generic _check_* helpers above read a flat/simplified shape and find nothing
    # in a real AWS export, so evaluate the AWS shape directly. Findings carry
    # their own per-agent attribution in evidence.
    if provider == "aws" and _is_aws_native(inventory):
        _extend(stats, findings, "CloudInventoryAgent",
                _check_aws_inventory(provider, scope, cfg, inventory, kind))

    # Azure Function App / GCP Cloud Function native inventory — the AWS-native
    # evaluator above only understands Lambda, so serverless checks for the other
    # two providers live in their own shape-aware evaluator.
    if (provider in ("azure", "gcp")
            and kind in ("cloud_account", "serverless_function")
            and _is_serverless_native(inventory, provider)):
        _extend(stats, findings, "ServerlessSecurityAgent",
                _check_cloud_functions(provider, scope, cfg, inventory))

    return findings, stats


def _empty_stats(
    provider: str,
    scope: str,
    credential_bound: bool,
    inventory: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    stats = {
        agent: {
            "role": role,
            "provider": provider,
            "scope": scope,
            "findings_count": 0,
        }
        for agent, role in AGENT_ROLES.items()
    }
    stats["CloudInventoryAgent"].update({
        "credential_bound": credential_bound,
        "inventory_sections": sorted(inventory.keys()),
    })
    return stats


def _extend(
    stats: dict[str, dict[str, Any]],
    findings: list[dict[str, Any]],
    agent: str,
    agent_findings: list[dict[str, Any]],
) -> None:
    stats.setdefault(agent, {"findings_count": 0})
    stats[agent]["findings_count"] = stats[agent].get("findings_count", 0) + len(agent_findings)
    findings.extend(agent_findings)


def _scope_for(cfg: dict[str, Any]) -> str:
    provider = str(cfg.get("provider") or "cloud")
    scope = cfg.get("account_id") or cfg.get("subscription_id") or cfg.get("project_id")
    return f"{provider}:{scope or 'unknown'}"


def _items(inventory: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for key in keys:
        raw = inventory.get(key)
        if isinstance(raw, dict):
            out.append(raw)
        elif isinstance(raw, list):
            out.extend(item for item in raw if isinstance(item, dict))
    return out


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "public", "enabled"}
    return bool(value)


def _falsey(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"0", "false", "no", "n", "disabled"}
    return value is False


def _name(resource: dict[str, Any], fallback: str) -> str:
    for key in ("name", "id", "arn", "resource_id", "principal", "domain"):
        value = resource.get(key)
        if value:
            return str(value)
    return fallback


def _actions(resource: dict[str, Any]) -> set[str]:
    raw = resource.get("actions") or resource.get("allowed_actions") or resource.get("permissions")
    if isinstance(raw, str):
        return {part.strip() for part in raw.split(",") if part.strip()}
    if isinstance(raw, Iterable):
        return {str(part).strip() for part in raw if str(part).strip()}
    return set()


def _check_iam(provider: str, scope: str, inventory: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for principal in _items(inventory, "iam", "principals", "roles", "policies"):
        actions = _actions(principal)
        has_wildcard = "*" in actions or "iam:*" in actions or _truthy(principal.get("wildcard_admin"))
        has_admin = _truthy(principal.get("admin")) or _truthy(principal.get("administrator"))
        has_passrole = "iam:PassRole" in actions or "iam:passrole" in {a.lower() for a in actions}
        if not (has_wildcard or has_admin or has_passrole):
            continue
        principal_name = _name(principal, "cloud principal")
        severity = "critical" if has_wildcard or has_admin else "high"
        findings.append(_finding(
            provider=provider,
            scope=scope,
            agent="CloudIamExposureAgent",
            title=f"Overbroad cloud IAM permissions: {principal_name}",
            severity=severity,
            category="cloud_iam",
            owasp_category="CIEM-01 Excessive Entitlements",
            description=(
                "A cloud principal has wildcard, administrator, or privilege-escalation "
                "permissions in the provided inventory metadata."
            ),
            remediation=(
                "Replace wildcard/admin grants with least-privilege policies, remove "
                "unneeded iam:PassRole-style escalation paths, and bind permissions to "
                "specific resources."
            ),
            evidence={
                "principal": principal_name,
                "actions": sorted(actions),
                "admin": has_admin,
                "wildcard": has_wildcard,
                "privilege_escalation_action": has_passrole,
            },
        ))
    return findings


def _check_storage(
    provider: str,
    scope: str,
    cfg: dict[str, Any],
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for bucket in _items(inventory, "storage", "buckets", "containers"):
        name = _name(bucket, "cloud storage")
        if cfg.get("check_public_access", True) and (
            _truthy(bucket.get("public")) or _truthy(bucket.get("public_access"))
        ):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="CloudStorageAgent",
                title=f"Cloud storage is publicly accessible: {name}",
                severity="high",
                category="cloud_storage",
                owasp_category="CSPM-02 Public Storage Exposure",
                description="A cloud storage resource is marked public in metadata.",
                remediation="Disable public access unless explicitly required and enforce bucket/container policies.",
                evidence={"resource": name, "public": True},
            ))
        if cfg.get("check_encryption", True) and _falsey(bucket.get("encrypted")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="CloudStorageAgent",
                title=f"Cloud storage encryption disabled: {name}",
                severity="medium",
                category="cloud_storage",
                owasp_category="CSPM-03 Data Encryption",
                description="A cloud storage resource is not encrypted at rest according to metadata.",
                remediation="Enable provider-managed or customer-managed encryption at rest.",
                evidence={"resource": name, "encrypted": False},
            ))
        if cfg.get("check_logging", True) and _falsey(bucket.get("logging_enabled")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="CloudStorageAgent",
                title=f"Cloud storage access logging disabled: {name}",
                severity="low",
                category="cloud_storage",
                owasp_category="CSPM-04 Audit Logging",
                description="A cloud storage resource does not have access logging enabled.",
                remediation="Enable access logs and route them to a protected logging destination.",
                evidence={"resource": name, "logging_enabled": False},
            ))
    return findings


def _check_serverless(
    provider: str,
    scope: str,
    cfg: dict[str, Any],
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    deprecated = {"nodejs10.x", "nodejs12.x", "python2.7", "python3.6", "dotnetcore2.1", "ruby2.5"}
    for function in _items(inventory, "functions", "serverless", "lambda"):
        name = _name(function, "serverless function")
        if cfg.get("check_public_invocation", True) and (
            _truthy(function.get("public_invocation")) or _truthy(function.get("anonymous_invocation"))
        ):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="ServerlessSecurityAgent",
                title=f"Serverless function allows public invocation: {name}",
                severity="high",
                category="serverless",
                owasp_category="SERVERLESS-01 Public Invocation",
                description="A serverless function can be invoked without a trusted identity boundary.",
                remediation="Require authenticated invocation and limit trigger principals to the expected callers.",
                evidence={"resource": name, "public_invocation": True},
            ))
        runtime = str(function.get("runtime") or "").strip()
        if cfg.get("check_runtime", True) and runtime.lower() in deprecated:
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="ServerlessSecurityAgent",
                title=f"Serverless function uses deprecated runtime: {name}",
                severity="medium",
                category="serverless",
                owasp_category="SERVERLESS-02 Runtime Hygiene",
                description="A serverless function uses a deprecated runtime.",
                remediation="Upgrade the function runtime to a currently supported version.",
                evidence={"resource": name, "runtime": runtime},
            ))
        env_keys = function.get("env_keys") or function.get("environment_keys") or []
        if cfg.get("include_env_metadata", True) and _contains_secret_key(env_keys):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="ServerlessSecurityAgent",
                title=f"Serverless environment contains secret-like keys: {name}",
                severity="medium",
                category="serverless",
                owasp_category="SERVERLESS-03 Secret Handling",
                description="Environment metadata includes secret-like variable names.",
                remediation="Move sensitive values into the provider secret manager and reference them at runtime.",
                evidence={"resource": name, "secret_like_env_keys": _secret_like_keys(env_keys)},
            ))
    return findings


def _check_edge(
    provider: str,
    scope: str,
    cfg: dict[str, Any],
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for edge in _items(inventory, "load_balancers", "cdn", "edges", "load_balancer_cdn"):
        name = _name(edge, "edge resource")
        tls = str(edge.get("tls_min_version") or edge.get("minimum_tls_version") or "").lower()
        if cfg.get("check_tls", True) and tls in {"tls1.0", "tls1.1", "1.0", "1.1"}:
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="EdgeCdnSecurityAgent",
                title=f"Edge endpoint allows legacy TLS: {name}",
                severity="medium",
                category="edge_cdn",
                owasp_category="EDGE-01 TLS Configuration",
                description="A load balancer or CDN endpoint permits legacy TLS versions.",
                remediation="Require TLS 1.2 or newer and disable weak ciphers.",
                evidence={"resource": name, "tls_min_version": tls},
            ))
        if cfg.get("check_waf", True) and _falsey(edge.get("waf_enabled")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="EdgeCdnSecurityAgent",
                title=f"Edge endpoint has no WAF policy: {name}",
                severity="medium",
                category="edge_cdn",
                owasp_category="EDGE-02 Missing WAF",
                description="A public load balancer or CDN endpoint does not have WAF protection enabled.",
                remediation="Attach a managed WAF policy and enable logging for blocked/allowed requests.",
                evidence={"resource": name, "waf_enabled": False},
            ))
        if cfg.get("check_origin_exposure", True) and _truthy(edge.get("origin_public")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="EdgeCdnSecurityAgent",
                title=f"CDN origin appears directly reachable: {name}",
                severity="high",
                category="edge_cdn",
                owasp_category="EDGE-03 Origin Exposure",
                description="A CDN or load balancer origin is marked publicly reachable in metadata.",
                remediation="Restrict origin access to the edge service using private links, signed origin headers, or security groups.",
                evidence={"resource": name, "origin_public": True},
            ))
        if cfg.get("check_cache_policy", True) and _truthy(edge.get("caches_authorized_content")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="EdgeCdnSecurityAgent",
                title=f"CDN cache policy may store authorized content: {name}",
                severity="medium",
                category="edge_cdn",
                owasp_category="EDGE-04 Cache Policy",
                description="A CDN cache policy is marked as caching authenticated or authorized responses.",
                remediation="Exclude Authorization/Cookie-bearing responses from cache or split public and private routes.",
                evidence={"resource": name, "caches_authorized_content": True},
            ))
    return findings


def _check_databases(
    provider: str,
    scope: str,
    cfg: dict[str, Any],
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for db in _items(inventory, "databases", "rds", "cloud_sql", "cosmos"):
        name = _name(db, "cloud database")
        if cfg.get("check_public_access", True) and (
            _truthy(db.get("public")) or _truthy(db.get("public_access"))
        ):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="CloudDatabaseAgent",
                title=f"Cloud database is publicly reachable: {name}",
                severity="critical",
                category="cloud_database",
                owasp_category="DSPM-01 Public Data Store",
                description="A managed database is marked publicly reachable in metadata.",
                remediation="Disable public access, restrict network paths to trusted private networks, and enforce database auth.",
                evidence={"resource": name, "public_access": True},
            ))
        if cfg.get("check_encryption", True) and _falsey(db.get("encrypted")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="CloudDatabaseAgent",
                title=f"Cloud database encryption disabled: {name}",
                severity="high",
                category="cloud_database",
                owasp_category="DSPM-02 Data Encryption",
                description="A managed database is not encrypted at rest according to metadata.",
                remediation="Enable encryption at rest and rotate any affected credentials after migration.",
                evidence={"resource": name, "encrypted": False},
            ))
        if cfg.get("check_backups", True) and _falsey(db.get("backups_enabled")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="CloudDatabaseAgent",
                title=f"Cloud database backups disabled: {name}",
                severity="medium",
                category="cloud_database",
                owasp_category="DSPM-03 Resilience",
                description="A managed database does not have backups enabled.",
                remediation="Enable automated backups and periodically test restore procedures.",
                evidence={"resource": name, "backups_enabled": False},
            ))
        if _falsey(db.get("deletion_protection")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="CloudDatabaseAgent",
                title=f"Cloud database deletion protection disabled: {name}",
                severity="low",
                category="cloud_database",
                owasp_category="DSPM-04 Change Protection",
                description="A managed database can be deleted without deletion protection.",
                remediation="Enable deletion protection on production databases.",
                evidence={"resource": name, "deletion_protection": False},
            ))
    return findings


def _check_secrets(
    provider: str,
    scope: str,
    cfg: dict[str, Any],
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for secret in _items(inventory, "secrets", "secret_managers", "key_vault"):
        name = _name(secret, "cloud secret")
        if cfg.get("check_rotation", True) and _falsey(secret.get("rotation_enabled")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="SecretsHygieneAgent",
                title=f"Secret rotation disabled: {name}",
                severity="medium",
                category="secrets_manager",
                owasp_category="SECRETS-01 Rotation",
                description="A secret metadata record shows rotation is disabled.",
                remediation="Enable automatic rotation or document and monitor a manual rotation cadence.",
                evidence={"resource": name, "rotation_enabled": False},
            ))
        if cfg.get("check_policy", True) and (
            _truthy(secret.get("policy_public")) or _truthy(secret.get("public_policy"))
        ):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="SecretsHygieneAgent",
                title=f"Secret policy allows public or broad access: {name}",
                severity="high",
                category="secrets_manager",
                owasp_category="SECRETS-02 Access Policy",
                description="A secret policy is marked public or broadly accessible in metadata.",
                remediation="Restrict secret access to the exact workload identities that require it.",
                evidence={"resource": name, "policy_public": True},
            ))
        if cfg.get("check_encryption", True) and _falsey(secret.get("encrypted")):
            findings.append(_finding(
                provider=provider,
                scope=scope,
                agent="SecretsHygieneAgent",
                title=f"Secret encryption metadata is disabled: {name}",
                severity="medium",
                category="secrets_manager",
                owasp_category="SECRETS-03 Encryption",
                description="A secret metadata record shows encryption is disabled or not configured.",
                remediation="Use provider-managed or customer-managed encryption keys for stored secrets.",
                evidence={"resource": name, "encrypted": False},
            ))
    return findings


def _check_audit_logging(
    provider: str,
    scope: str,
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    audit = inventory.get("audit_logging") or inventory.get("logging")
    if not isinstance(audit, dict):
        return findings
    if _falsey(audit.get("enabled")):
        findings.append(_finding(
            provider=provider,
            scope=scope,
            agent="CloudAuditLoggingAgent",
            title="Cloud account audit logging disabled",
            severity="high",
            category="cloud_logging",
            owasp_category="CSPM-04 Audit Logging",
            description="Account-level cloud audit logging is disabled according to metadata.",
            remediation="Enable provider audit logging in every region and protect log sinks from deletion.",
            evidence={"audit_logging_enabled": False},
        ))
    if _falsey(audit.get("log_integrity_validation")):
        findings.append(_finding(
            provider=provider,
            scope=scope,
            agent="CloudAuditLoggingAgent",
            title="Cloud audit log integrity validation disabled",
            severity="medium",
            category="cloud_logging",
            owasp_category="CSPM-04 Audit Logging",
            description="Audit log integrity validation is disabled according to metadata.",
            remediation="Enable log file validation or immutable log storage where supported.",
            evidence={"log_integrity_validation": False},
        ))
    return findings


def _contains_secret_key(keys: Any) -> bool:
    return bool(_secret_like_keys(keys))


def _secret_like_keys(keys: Any) -> list[str]:
    if isinstance(keys, dict):
        raw_keys = keys.keys()
    elif isinstance(keys, list | tuple | set):
        raw_keys = keys
    else:
        return []
    out: list[str] = []
    for key in raw_keys:
        lowered = str(key).lower()
        if any(token in lowered for token in ("secret", "password", "token", "apikey", "api_key", "access_key", "private_key")):
            out.append(str(key))
    return sorted(out)


def _is_aws_native(inventory: dict[str, Any]) -> bool:
    """True when the inventory is the AWS-native export shape (resources nested
    under ``resources`` with AWS keys) rather than the generic flat shape the
    _check_* helpers consume."""
    if not isinstance(inventory, dict):
        return False
    res = inventory.get("resources")
    if isinstance(res, dict) and any(
        k in res for k in ("s3_buckets", "rds", "rds_instances", "dynamodb_tables",
                           "elasticache_clusters", "ec2", "cloudtrail", "iam", "vpc",
                           "lambda_functions", "iam_roles", "load_balancers", "cloudfront_distributions",
                           "secrets_manager", "secrets_manager_secrets", "kms", "guardduty",
                           "config", "securityhub", "access_analyzer")
    ):
        return True
    return any(k in inventory for k in ("s3_buckets", "rds", "cloudtrail", "lambda_functions"))


def _principal_is_public(principal: Any) -> bool:
    """True when an IAM/resource-policy Principal grants access to everyone.

    Handles the wildcard string ``"*"`` and the object forms
    ``{"AWS": "*"}`` / ``{"AWS": ["*", ...]}`` / ``{"Service": ...}``.
    """
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for v in principal.values():
            if v == "*" or (isinstance(v, (list, tuple, set)) and "*" in v):
                return True
    return False


def _policy_allow_statements(policy: Any) -> list[dict[str, Any]]:
    """Allow-effect statements of a resource policy (dict or {Statement:[...]})."""
    if not isinstance(policy, dict):
        return []
    stmts = policy.get("Statement")
    stmts = stmts if isinstance(stmts, list) else ([policy] if "Principal" in policy else [])
    return [s for s in stmts if isinstance(s, dict) and str(s.get("Effect", "Allow")).lower() == "allow"]


def _policy_is_public(policy: Any) -> bool:
    """True when any Allow statement grants a public (``*``) principal."""
    return any(_principal_is_public(s.get("Principal")) for s in _policy_allow_statements(policy))


def _policy_cross_account(policy: Any, account_id: str | None) -> list[str]:
    """External-account principal ARNs granted by the policy (excludes ``*`` and
    the owning ``account_id``)."""
    if not account_id:
        return []
    out: list[str] = []
    for s in _policy_allow_statements(policy):
        pr = s.get("Principal")
        vals: list[Any] = []
        if isinstance(pr, dict):
            for v in pr.values():
                vals += list(v) if isinstance(v, (list, tuple, set)) else [v]
        elif isinstance(pr, str):
            vals = [pr]
        for a in vals:
            a = str(a)
            if a != "*" and ":" in a and str(account_id) not in a:
                out.append(a)
    return sorted(set(out))


# Deprecated/unsupported runtimes across AWS/Azure/GCP, compared against a
# normalized form (lowercased, non-alphanumerics stripped) so "python3.6",
# "python|3.6" (Azure linuxFxVersion), and "python36" (GCP) all match.
_DEPRECATED_RUNTIMES = frozenset({
    "python27", "python36", "python37",
    "node8", "node810", "node10", "node12",
    "nodejs8", "nodejs810", "nodejs10", "nodejs10x", "nodejs12", "nodejs12x",
    "go111", "go112", "go113", "go116",
    "dotnet2", "dotnet22", "dotnetcore21", "dotnetcore31",
    "ruby25", "ruby26",
})
# Role names that grant far more than a single function needs. Substring match,
# lowercased: AWS AdministratorAccess, Azure Owner/Contributor, GCP owner/editor.
_PRIVILEGED_ROLE_TOKENS = (
    "administratoraccess", "roles/owner", "roles/editor",
    "owner", "contributor", "useraccessadministrator",
)


def _norm_runtime(runtime: Any) -> str:
    return "".join(ch for ch in str(runtime or "").lower() if ch.isalnum())


def _runtime_is_deprecated(runtime: Any) -> bool:
    return _norm_runtime(runtime) in _DEPRECATED_RUNTIMES


def _privileged_roles(names: Any) -> list[str]:
    out: list[str] = []
    for n in names or []:
        low = str(n).lower().replace(" ", "")
        if any(tok in low for tok in _PRIVILEGED_ROLE_TOKENS):
            out.append(str(n))
    return sorted(set(out))


def _is_serverless_native(inventory: dict[str, Any], provider: str) -> bool:
    """True when an Azure/GCP inventory carries a serverless function list."""
    if not isinstance(inventory, dict):
        return False
    res = inventory.get("resources") if isinstance(inventory.get("resources"), dict) else inventory
    keys = {
        "azure": ("function_apps", "azure_functions", "functions"),
        "gcp": ("cloud_functions", "gcp_functions", "functions"),
    }.get(provider, ())
    return any(isinstance(res.get(k), list) and res.get(k) for k in keys)


def _function_is_public(provider: str, fn: dict[str, Any]) -> bool:
    if provider == "azure":
        if str(fn.get("auth_level", "")).lower() == "anonymous":
            return True
        return _truthy(fn.get("anonymous_access")) or _truthy(fn.get("public_access"))
    if provider == "gcp":
        if _truthy(fn.get("allow_unauthenticated")):
            return True
        members = list(fn.get("members") or [])
        for b in ((fn.get("iam_policy") or {}).get("bindings") or []):
            members += list(b.get("members") or [])
        return any(str(m).lower() in ("allusers", "allauthenticatedusers") for m in members)
    return False


def _check_cloud_functions(
    provider: str, scope: str, cfg: dict[str, Any], inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    """Azure Function App / GCP Cloud Function posture from an offline inventory.

    Mirrors the AWS Lambda checks (public invocation, deprecated runtime,
    secret-like env/app-settings, over-privileged identity) and emits the same
    evidence keys as the AWS path so the finding-detail LOCUS/EVIDENCE panels
    populate identically.
    """
    res = inventory.get("resources") if isinstance(inventory.get("resources"), dict) else inventory
    F: list[dict[str, Any]] = []

    if provider == "azure":
        fns = res.get("function_apps") or res.get("azure_functions") or res.get("functions") or []
        label, secret_store = "Function App", "Azure Key Vault references"
        roles_by_id: dict[str, list[str]] = {}
        for ra in res.get("role_assignments") or []:
            pid = ra.get("principal_id") or ra.get("principalId")
            if pid:
                roles_by_id.setdefault(str(pid), []).append(
                    ra.get("role") or ra.get("role_definition_name") or ra.get("roleDefinitionName") or "")
    else:  # gcp
        fns = res.get("cloud_functions") or res.get("gcp_functions") or res.get("functions") or []
        label, secret_store = "Cloud Function", "Google Secret Manager"
        roles_by_id = {}
        for sa in res.get("service_accounts") or []:
            key = sa.get("email") or sa.get("name")
            if key:
                roles_by_id[str(key)] = list(sa.get("roles") or [])

    for fn in fns:
        if not isinstance(fn, dict):
            continue
        name = fn.get("name") or fn.get("function_name") or fn.get("id") or label.lower()
        if cfg.get("check_public_invocation", True) and _function_is_public(provider, fn):
            F.append(_finding(provider=provider, scope=scope, agent="ServerlessSecurityAgent",
                title=f"Serverless function allows public invocation: {name}", severity="high",
                category="serverless", owasp_category="SERVERLESS-01 Public Invocation",
                description=f"The {label} can be invoked without a trusted identity boundary "
                            "(anonymous auth / allUsers binding).",
                remediation="Require authenticated invocation; remove anonymous auth or allUsers/allAuthenticatedUsers bindings.",
                evidence={"resource": name, "public_invocation": True}))
        rt = fn.get("runtime") or fn.get("linux_fx_version") or fn.get("linuxFxVersion") or ""
        if cfg.get("check_runtime", True) and _runtime_is_deprecated(rt):
            F.append(_finding(provider=provider, scope=scope, agent="ServerlessSecurityAgent",
                title=f"Serverless function uses deprecated runtime: {name}", severity="medium",
                category="serverless", owasp_category="SERVERLESS-02 Runtime Hygiene",
                description=f"The {label} runs on '{rt}', a deprecated/unsupported runtime.",
                remediation="Upgrade the function to a currently supported runtime version.",
                evidence={"resource": name, "runtime": str(rt)}))
        env = fn.get("app_settings") if provider == "azure" else fn.get("environment_variables")
        env = env or fn.get("environment_variables") or fn.get("app_settings")
        secret_keys = _secret_like_keys(env)
        if cfg.get("include_env_metadata", True) and secret_keys:
            F.append(_finding(provider=provider, scope=scope, agent="ServerlessSecurityAgent",
                title=f"Serverless environment contains secret-like keys: {name}", severity="medium",
                category="serverless", owasp_category="SERVERLESS-03 Secret Handling",
                description="Environment/app settings include secret-like names; plaintext config is not a secret store.",
                remediation=f"Move secrets into {secret_store} and reference them at runtime.",
                evidence={"resource": name, "secret_like_env_keys": secret_keys}))
        if provider == "azure":
            role_names = list(fn.get("identity_roles") or fn.get("role_assignments") or [])
            ident = fn.get("identity") if isinstance(fn.get("identity"), dict) else {}
            pid = ident.get("principal_id") or ident.get("principalId") or fn.get("principal_id")
            if pid:
                role_names += roles_by_id.get(str(pid), [])
        else:
            role_names = list(fn.get("service_account_roles") or [])
            sa = fn.get("service_account_email") or fn.get("service_account")
            if sa:
                role_names += roles_by_id.get(str(sa), [])
        priv = _privileged_roles(role_names)
        if priv:
            F.append(_finding(provider=provider, scope=scope, agent="ServerlessSecurityAgent",
                title=f"Serverless function has over-privileged identity: {name}", severity="high",
                category="serverless", owasp_category="CIEM-01 Excessive Entitlements",
                description=f"The {label} identity holds privileged roles: {', '.join(priv)}.",
                remediation="Scope the function identity/service account to least privilege for its actual needs.",
                evidence={"resource": name, "role": ", ".join(priv)}))
    return F


def _check_aws_inventory(
    provider: str,
    scope: str,
    cfg: dict[str, Any],
    inventory: dict[str, Any],
    kind: str = "cloud_account",
) -> list[dict[str, Any]]:
    """CSPM evaluation of an AWS-native offline inventory (no live credentials).

    The generic _check_* helpers read a flat/simplified inventory and miss the
    real AWS export shape (``resources.{s3_buckets,rds,ec2,iam,cloudtrail,...}``),
    so an offline AWS inventory scanned nothing. This evaluates the AWS shape
    directly against standard CIS-benchmark misconfigurations.

    ``kind`` scopes which sections run: a full ``cloud_account`` runs everything,
    but a narrow target (e.g. ``serverless_function``) runs only its own section
    so a Lambda scan doesn't emit account-wide findings like "CloudTrail not
    enabled" inferred from an inventory that only listed functions.
    """
    res = inventory.get("resources") if isinstance(inventory.get("resources"), dict) else inventory
    services = {str(s).lower() for s in (cfg.get("services") or [])}
    want = lambda name: (not services) or name in services  # noqa: E731
    # None => cloud_account => all sections in scope. A narrow kind restricts
    # to its own section(s) regardless of the include_* cfg defaults.
    _KIND_SECTIONS = {
        "serverless_function": {"serverless"},
        "cloud_storage": {"storage"},
        "cloud_database": {"database"},
        "secrets_manager": {"secrets"},
        "load_balancer_cdn": {"edge"},
    }
    _allowed = _KIND_SECTIONS.get(kind)
    sect = lambda name: (_allowed is None) or (name in _allowed)  # noqa: E731
    F: list[dict[str, Any]] = []

    def add(agent, title, severity, category, owasp, desc, remediation, evidence):
        F.append(_finding(provider=provider, scope=scope, agent=agent, title=title,
                          severity=severity, category=category, owasp_category=owasp,
                          description=desc, remediation=remediation, evidence=evidence))

    def _admin(policies) -> bool:
        return any("AdministratorAccess" in str(p) for p in (policies or []))

    # ── IAM ──────────────────────────────────────────────────────────
    iam = res.get("iam") if isinstance(res.get("iam"), dict) else {}
    if sect("iam") and want("iam") and iam:
        root = iam.get("root_account") or {}
        if root:
            if _falsey(root.get("mfa_enabled")):
                add("CloudIamExposureAgent", "Root account MFA is disabled", "critical",
                    "cloud_iam", "CIS-1.5 Root MFA",
                    "The AWS account root user does not have MFA enabled.",
                    "Enable a hardware or virtual MFA device on the root user immediately.",
                    {"resource": "root", "mfa_enabled": False})
            if _truthy(root.get("access_keys_active")):
                add("CloudIamExposureAgent", "Root account has active access keys", "critical",
                    "cloud_iam", "CIS-1.4 Root Access Keys",
                    "The root user has active access keys — a full-account credential that should never exist.",
                    "Delete all root access keys; use IAM roles/users for programmatic access.",
                    {"resource": "root", "access_keys_active": True})
        for u in iam.get("users") or []:
            name = u.get("username") or u.get("arn") or "iam-user"
            if _falsey(u.get("mfa_enabled")):
                add("CloudIamExposureAgent", f"IAM user without MFA: {name}", "high",
                    "cloud_iam", "CIS-1.10 IAM MFA",
                    "An IAM user with console/API access has no MFA device.",
                    "Require MFA for all IAM users; enforce via an IAM policy condition.",
                    {"user": name, "mfa_enabled": False})
            if _admin(u.get("attached_policies")):
                add("CloudIamExposureAgent", f"IAM user with AdministratorAccess: {name}", "high",
                    "cloud_iam", "CIEM-01 Excessive Entitlements",
                    "An IAM user is directly attached to AdministratorAccess (full account admin).",
                    "Replace with least-privilege policies; grant admin only via assumable roles.",
                    {"user": name, "attached_policies": u.get("attached_policies")})
            for k in u.get("access_keys") or []:
                age = k.get("age_days") or 0
                if isinstance(age, (int, float)) and age > 90:
                    add("CloudIamExposureAgent", f"IAM access key older than 90 days: {name}",
                        "high" if age > 365 else "medium", "cloud_iam", "CIS-1.14 Key Rotation",
                        f"Access key {k.get('key_id','?')} is {int(age)} days old without rotation.",
                        "Rotate access keys at least every 90 days and remove unused keys.",
                        {"user": name, "key_id": k.get("key_id"), "age_days": age})
        for r in iam.get("roles") or []:
            if _admin(r.get("attached_policies")):
                add("CloudIamExposureAgent", f"IAM role with AdministratorAccess: {r.get('name','role')}",
                    "high", "cloud_iam", "CIEM-01 Excessive Entitlements",
                    "An IAM role is attached to AdministratorAccess.",
                    "Scope the role to least-privilege permissions for its workload.",
                    {"role": r.get("name"), "attached_policies": r.get("attached_policies")})
        pw = iam.get("password_policy") or {}
        if pw:
            weak = []
            if (pw.get("minimum_length") or 0) < 14:
                weak.append(f"min_length={pw.get('minimum_length')}")
            for req in ("require_symbols", "require_numbers", "require_uppercase", "require_lowercase"):
                if _falsey(pw.get(req)):
                    weak.append(req.replace("require_", "no_"))
            if not pw.get("password_reuse_prevention"):
                weak.append("no_reuse_prevention")
            if weak:
                add("CloudIamExposureAgent", "Weak IAM password policy", "medium",
                    "cloud_iam", "CIS-1.8 Password Policy",
                    f"The account password policy is weak: {', '.join(weak)}.",
                    "Enforce length >= 14, complexity, and reuse prevention >= 24.",
                    {"weaknesses": weak})

    # ── Storage (S3) ─────────────────────────────────────────────────
    if sect("storage") and want("storage"):
        for b in res.get("s3_buckets") or []:
            name = b.get("name") or "s3-bucket"
            acl = str(b.get("acl") or "").lower()
            pab = b.get("public_access_block") or {}
            pab_off = pab and not any(_truthy(pab.get(k)) for k in pab)
            policy_public = isinstance(b.get("policy"), dict) and any(
                st.get("Principal") == "*" for st in (b["policy"].get("Statement") or [])
                if isinstance(st, dict))
            if acl in {"public-read", "public-read-write"} or pab_off or policy_public:
                sev = "critical" if acl == "public-read-write" else "high"
                add("CloudStorageAgent", f"S3 bucket publicly accessible: {name}", sev,
                    "cloud_storage", "CSPM-02 Public Storage Exposure",
                    f"S3 bucket '{name}' is public (acl={acl or 'n/a'}, public_access_block off={bool(pab_off)}, policy_public={policy_public}).",
                    "Enable S3 Block Public Access at the account+bucket level and remove public ACLs/policies.",
                    {"bucket": name, "acl": acl, "public_access_block_off": bool(pab_off), "policy_public": policy_public})
            if not b.get("encryption"):
                add("CloudStorageAgent", f"S3 bucket not encrypted at rest: {name}", "medium",
                    "cloud_storage", "CSPM-03 Data Encryption",
                    f"S3 bucket '{name}' has no default encryption.",
                    "Enable SSE-S3 or SSE-KMS default encryption.",
                    {"bucket": name})
            if str(b.get("versioning") or "").lower() == "disabled":
                add("CloudStorageAgent", f"S3 bucket versioning disabled: {name}", "low",
                    "cloud_storage", "CSPM-04 Data Durability",
                    f"S3 bucket '{name}' has versioning disabled.",
                    "Enable versioning to protect against overwrite/deletion.",
                    {"bucket": name})

    # ── Databases (RDS / DynamoDB / ElastiCache) ─────────────────────
    if sect("database") and want("database"):
        # Accept BOTH the nested (resources.rds.instances) and the flat
        # (resources.rds_instances) AWS export shapes.
        for db in (list((res.get("rds") or {}).get("instances") or [])
                   + list(res.get("rds_instances") or [])):
            name = db.get("identifier") or "rds-instance"
            # storage_encrypted is the canonical RDS field; fall back to the
            # generic "encrypted". Unencrypted only when neither is truthy.
            unencrypted = _falsey(db.get("storage_encrypted")) and _falsey(db.get("encrypted"))
            if _truthy(db.get("publicly_accessible")):
                add("CloudDatabaseAgent", f"RDS instance is publicly accessible: {name}",
                    "critical" if unencrypted else "high",
                    "cloud_database", "CSPM-05 Public Database",
                    f"RDS instance '{name}' is reachable from the public internet"
                    + (" and its storage is unencrypted." if unencrypted else "."),
                    "Set publicly_accessible=false and restrict the DB to private subnets/security groups.",
                    {"instance": name, "publicly_accessible": True,
                     "storage_encrypted": _truthy(db.get("storage_encrypted") or db.get("encrypted"))})
            if unencrypted:
                add("CloudDatabaseAgent", f"RDS instance not encrypted at rest: {name}", "high",
                    "cloud_database", "CSPM-03 Data Encryption",
                    f"RDS instance '{name}' storage is not encrypted at rest.",
                    "Enable RDS storage encryption (KMS); restore into an encrypted instance.",
                    {"instance": name, "storage_encrypted": False})
            if (db.get("backup_retention_days") or 0) == 0:
                add("CloudDatabaseAgent", f"RDS backups disabled: {name}", "medium",
                    "cloud_database", "CSPM-04 Data Durability",
                    f"RDS instance '{name}' has automated backups disabled (retention 0).",
                    "Set backup retention to >= 7 days.",
                    {"instance": name, "backup_retention_days": db.get("backup_retention_days") or 0})
            if _falsey(db.get("deletion_protection")):
                add("CloudDatabaseAgent", f"RDS deletion protection disabled: {name}", "low",
                    "cloud_database", "CSPM-06 Change Protection",
                    f"RDS instance '{name}' can be deleted without deletion protection.",
                    "Enable deletion protection on production databases.",
                    {"instance": name, "deletion_protection": False})
            if _falsey(db.get("iam_authentication")):
                add("CloudDatabaseAgent", f"RDS IAM database authentication disabled: {name}", "low",
                    "cloud_database", "CIEM-02 Database Auth",
                    f"RDS instance '{name}' relies on native DB credentials (IAM auth off).",
                    "Enable IAM database authentication to centralize and rotate access.",
                    {"instance": name, "iam_authentication": False})

        # ── DynamoDB tables ──────────────────────────────────────────
        for tbl in res.get("dynamodb_tables") or []:
            name = tbl.get("name") or "dynamodb-table"
            enc = tbl.get("encryption") if isinstance(tbl.get("encryption"), dict) else {}
            data_class = str((tbl.get("tags") or {}).get("DataClass", "")).lower()
            sensitive = data_class in {"pci", "confidential", "phi"}
            if _falsey(enc.get("enabled")):
                add("CloudDatabaseAgent", f"DynamoDB table not encrypted with a customer-managed key: {name}",
                    "high" if sensitive else "medium",
                    "cloud_database", "CSPM-03 Data Encryption",
                    f"DynamoDB table '{name}' has customer-managed encryption disabled "
                    f"(type={enc.get('type') or 'DEFAULT'})"
                    + (f"; table is tagged DataClass={data_class}." if sensitive else "."),
                    "Enable KMS (customer-managed key) encryption on the table.",
                    {"table": name, "encryption": enc,
                     "data_class": (tbl.get("tags") or {}).get("DataClass")})
            if _falsey(tbl.get("point_in_time_recovery")):
                add("CloudDatabaseAgent", f"DynamoDB point-in-time recovery disabled: {name}", "low",
                    "cloud_database", "CSPM-04 Data Durability",
                    f"DynamoDB table '{name}' has point-in-time recovery (PITR) disabled.",
                    "Enable PITR for continuous backups and 35-day restore.",
                    {"table": name, "point_in_time_recovery": False})
            if _falsey(tbl.get("deletion_protection")):
                add("CloudDatabaseAgent", f"DynamoDB deletion protection disabled: {name}", "low",
                    "cloud_database", "CSPM-06 Change Protection",
                    f"DynamoDB table '{name}' can be deleted without deletion protection.",
                    "Enable deletion protection on production tables.",
                    {"table": name, "deletion_protection": False})

        # ── ElastiCache clusters ─────────────────────────────────────
        for cl in res.get("elasticache_clusters") or []:
            name = cl.get("cluster_id") or cl.get("name") or "elasticache-cluster"
            engine = str(cl.get("engine") or "").lower()
            if _falsey(cl.get("at_rest_encryption")):
                add("CloudDatabaseAgent", f"ElastiCache at-rest encryption disabled: {name}", "medium",
                    "cloud_database", "CSPM-03 Data Encryption",
                    f"ElastiCache cluster '{name}' has at-rest encryption disabled.",
                    "Recreate the cluster with at-rest encryption enabled.",
                    {"cluster": name, "at_rest_encryption": False})
            if _falsey(cl.get("in_transit_encryption")):
                add("CloudDatabaseAgent", f"ElastiCache in-transit encryption disabled: {name}", "medium",
                    "cloud_database", "CSPM-03 Data Encryption",
                    f"ElastiCache cluster '{name}' has in-transit (TLS) encryption disabled.",
                    "Enable in-transit (TLS) encryption on the cluster.",
                    {"cluster": name, "in_transit_encryption": False})
            if engine == "redis" and _falsey(cl.get("auth_token_enabled")):
                add("CloudDatabaseAgent", f"ElastiCache Redis AUTH token disabled: {name}", "high",
                    "cloud_database", "CIEM-02 Database Auth",
                    f"Redis cluster '{name}' has no AUTH token — the data path accepts unauthenticated commands.",
                    "Enable a Redis AUTH token together with in-transit encryption to protect it.",
                    {"cluster": name, "auth_token_enabled": False})

    # ── Network exposure (security groups / EBS / VPC) ───────────────
    if sect("edge") and (want("edge") or _truthy(cfg.get("include_network", True))):
        ec2 = res.get("ec2") if isinstance(res.get("ec2"), dict) else {}
        for sg in ec2.get("security_groups") or []:
            gname = sg.get("group_name") or sg.get("group_id") or "sg"
            for rule in sg.get("inbound_rules") or []:
                if str(rule.get("source")) != "0.0.0.0/0":
                    continue
                port = str(rule.get("port_range") or "")
                proto = str(rule.get("protocol") or "")
                if proto in {"-1", "all"} or port.lower() == "all":
                    add("EdgeCdnSecurityAgent", f"Security group open to the internet (all ports): {gname}",
                        "critical", "cloud_network", "CSPM-06 Network Exposure",
                        f"Security group '{gname}' allows ALL inbound traffic from 0.0.0.0/0.",
                        "Restrict inbound rules to specific source ranges and required ports only.",
                        {"security_group": gname, "port_range": port or "all", "protocol": proto})
                elif port in {"22", "3389"}:
                    add("EdgeCdnSecurityAgent", f"Security group exposes {'SSH' if port=='22' else 'RDP'} to the internet: {gname}",
                        "high", "cloud_network", "CSPM-06 Network Exposure",
                        f"Security group '{gname}' allows inbound {port}/tcp from 0.0.0.0/0.",
                        "Limit management ports to a bastion/VPN CIDR; never 0.0.0.0/0.",
                        {"security_group": gname, "port_range": port})
        for inst in ec2.get("instances") or []:
            for vol in inst.get("volumes") or []:
                if _falsey(vol.get("encrypted")):
                    add("EdgeCdnSecurityAgent", f"Unencrypted EBS volume: {vol.get('volume_id','vol')}",
                        "medium", "cloud_network", "CSPM-03 Data Encryption",
                        "An EBS volume is not encrypted at rest.",
                        "Enable EBS encryption (account default + per-volume).",
                        {"volume_id": vol.get("volume_id"), "instance_id": inst.get("instance_id")})
        vpc = res.get("vpc") if isinstance(res.get("vpc"), dict) else {}
        if vpc and _falsey(vpc.get("flow_logs_enabled")):
            add("EdgeCdnSecurityAgent", "VPC flow logs disabled", "low",
                "cloud_network", "CSPM-07 Logging",
                "VPC flow logs are not enabled, reducing network forensic visibility.",
                "Enable VPC flow logs to a central log destination.",
                {"flow_logs_enabled": False})

    # ── Audit logging / detective controls ───────────────────────────
    if sect("audit_logging") and (want("audit_logging") or _truthy(cfg.get("include_audit_logging", True))):
        ct = res.get("cloudtrail") if isinstance(res.get("cloudtrail"), dict) else {}
        trails = ct.get("trails") or []
        if not trails:
            add("CloudAuditLoggingAgent", "CloudTrail is not enabled", "high",
                "cloud_audit", "CIS-3.1 Audit Logging",
                "No CloudTrail trail is configured for the account.",
                "Enable a multi-region CloudTrail with log file validation.",
                {"trails": 0})
        for tr in trails:
            if _falsey(tr.get("is_multi_region")):
                add("CloudAuditLoggingAgent", f"CloudTrail not multi-region: {tr.get('name','trail')}",
                    "medium", "cloud_audit", "CIS-3.1 Audit Logging",
                    "A CloudTrail trail is not multi-region, so some regions are unlogged.",
                    "Enable is_multi_region on the trail.",
                    {"trail": tr.get("name")})
            if _falsey(tr.get("log_file_validation")):
                add("CloudAuditLoggingAgent", f"CloudTrail log file validation disabled: {tr.get('name','trail')}",
                    "medium", "cloud_audit", "CIS-3.2 Log Integrity",
                    "CloudTrail log file validation is off — logs are not tamper-evident.",
                    "Enable log file validation on the trail.",
                    {"trail": tr.get("name")})
        for svc, sev in (("config", "medium"), ("guardduty", "medium"),
                         ("securityhub", "low"), ("access_analyzer", "low")):
            node = res.get(svc) if isinstance(res.get(svc), dict) else {}
            if node and _falsey(node.get("enabled")):
                add("CloudAuditLoggingAgent", f"{svc} is disabled", sev,
                    "cloud_audit", "CIS-3 Detective Controls",
                    f"AWS {svc} is not enabled for the account.",
                    f"Enable {svc} across all regions.",
                    {"service": svc, "enabled": False})

    # ── Secrets / KMS hygiene ────────────────────────────────────────
    if sect("secrets") and want("secrets"):
        acct = inventory.get("account_id") or cfg.get("account_id")
        # Accept BOTH the nested (resources.secrets_manager.secrets) and the flat
        # (resources.secrets_manager_secrets) AWS export shapes.
        for s in (list((res.get("secrets_manager") or {}).get("secrets") or [])
                  + list(res.get("secrets_manager_secrets") or [])):
            name = s.get("name") or "secret"
            data_class = str((s.get("tags") or {}).get("DataClass", "")).lower()
            sensitive = data_class in {"pci", "confidential", "phi"}
            policy = s.get("resource_policy") or s.get("policy")
            # Public resource policy — anyone can read the secret value.
            if _policy_is_public(policy):
                add("SecretsHygieneAgent", f"Secret resource policy is public: {name}", "critical",
                    "cloud_secrets", "SECRETS-02 Access Policy",
                    f"Secret '{name}' has a resource policy granting access to '*' (public) — "
                    "anyone can retrieve the secret value.",
                    "Restrict the secret's resource policy to the exact workload principals that need it.",
                    {"secret": name, "policy_public": True, "data_class": data_class or None})
            # Cross-account access — explicit list or derived from the policy.
            xacct = list(s.get("cross_account_principals") or []) + _policy_cross_account(policy, acct)
            if xacct:
                add("SecretsHygieneAgent", f"Secret shared cross-account: {name}", "high",
                    "cloud_secrets", "SECRETS-02 Access Policy",
                    f"Secret '{name}' grants access to principals outside account {acct}: "
                    f"{', '.join(sorted(set(str(p) for p in xacct)))}.",
                    "Remove external-account grants unless a reviewed sharing requirement exists.",
                    {"secret": name, "cross_account_principals": sorted(set(str(p) for p in xacct))})
            # No customer-managed key — encrypted with the AWS-managed default key.
            if not s.get("kms_key_id"):
                add("SecretsHygieneAgent", f"Secret not encrypted with a customer-managed key: {name}",
                    "high" if sensitive else "medium",
                    "cloud_secrets", "SECRETS-03 Encryption",
                    f"Secret '{name}' uses the AWS-managed default key (no customer-managed KMS key)"
                    + (f"; tagged DataClass={data_class}." if sensitive else "."),
                    "Encrypt the secret with a customer-managed KMS key for control + audit.",
                    {"secret": name, "kms_key_id": None, "data_class": data_class or None})
            # Immediate, unrecoverable deletion window.
            rw = s.get("recovery_window_days")
            if rw is not None and isinstance(rw, (int, float)) and rw <= 0:
                add("SecretsHygieneAgent", f"Secret deletion has no recovery window: {name}", "medium",
                    "cloud_secrets", "SECRETS-04 Recoverability",
                    f"Secret '{name}' is configured for immediate deletion (recovery window 0) — "
                    "an accidental or malicious delete is unrecoverable.",
                    "Set a recovery window of at least 7 days on secret deletion.",
                    {"secret": name, "recovery_window_days": rw})
            # Rotation — escalate for stale, sensitive secrets. Staleness is read
            # from last_rotated_days, else age_days; a null last_rotated_date with
            # no last_rotated_days means the secret was never rotated.
            if _falsey(s.get("rotation_enabled")):
                last = s.get("last_rotated_days")
                if last is None and isinstance(s.get("age_days"), (int, float)):
                    last = s.get("age_days")
                never = not s.get("last_rotated_date") and s.get("last_rotated_days") is None
                stale = never or (isinstance(last, (int, float)) and last > 90)
                when = (" (never rotated)." if never
                        else f" (last rotated {int(last)} days ago)." if isinstance(last, (int, float))
                        else ".")
                add("SecretsHygieneAgent", f"Secret rotation disabled: {name}",
                    "high" if (sensitive and stale) else "medium",
                    "cloud_secrets", "SECRETS-01 Rotation",
                    f"Secret '{name}' has automatic rotation disabled" + when,
                    "Enable automatic rotation on the secret.",
                    {"secret": name, "rotation_enabled": False,
                     "last_rotated_date": s.get("last_rotated_date"), "age_days": s.get("age_days")})
        for k in (res.get("kms") or {}).get("keys") or []:
            key_id = k.get("key_id") or "key"
            # Public KMS key policy — anyone can use the key to encrypt/decrypt.
            if _policy_is_public(k.get("policy")):
                add("SecretsHygieneAgent", f"KMS key policy is public: {key_id}", "critical",
                    "cloud_secrets", "SECRETS-02 Access Policy",
                    f"KMS key '{key_id}' has a key policy granting '*' (public) — "
                    "anyone can use it to decrypt data it protects.",
                    "Scope the KMS key policy to specific principals; never grant Principal '*'.",
                    {"key_id": key_id, "policy_public": True})
            if _falsey(k.get("rotation_enabled")):
                add("SecretsHygieneAgent", f"KMS key rotation disabled: {key_id}",
                    "low", "cloud_secrets", "CSPM-03 Key Management",
                    "A customer KMS key does not have annual rotation enabled.",
                    "Enable automatic key rotation.",
                    {"key_id": key_id})

    # ── Lambda / serverless functions ────────────────────────────────
    # Runs for both cloud_account (services includes 'serverless') and
    # serverless_function targets (no services filter → want() is True).
    if sect("serverless") and (want("serverless") or want("lambda")):
        roles_by_key: dict[str, dict[str, Any]] = {}
        for r in res.get("iam_roles") or []:
            for key in (r.get("arn"), r.get("role_name"), r.get("name")):
                if key:
                    roles_by_key[key] = r
        for fn in res.get("lambda_functions") or []:
            name = fn.get("function_name") or fn.get("name") or fn.get("arn") or "lambda"
            stmts = (fn.get("resource_policy") or {}).get("Statement") or []
            if isinstance(stmts, dict):
                stmts = [stmts]
            if any(str(s.get("Effect", "")).lower() == "allow"
                   and _principal_is_public(s.get("Principal")) for s in stmts):
                add("ServerlessSecurityAgent", f"Serverless function allows public invocation: {name}",
                    "high", "serverless", "SERVERLESS-01 Public Invocation",
                    "The function resource policy allows invocation by any principal (Principal '*').",
                    "Restrict the resource policy to specific trusted principals or source ARNs.",
                    {"resource": name, "public_invocation": True})
            rt = str(fn.get("runtime") or "").strip()
            if _runtime_is_deprecated(rt):
                add("ServerlessSecurityAgent", f"Serverless function uses deprecated runtime: {name}",
                    "medium", "serverless", "SERVERLESS-02 Runtime Hygiene",
                    f"The function runs on '{rt}', a deprecated/unsupported runtime.",
                    "Upgrade the function to a currently supported runtime version.",
                    {"resource": name, "runtime": rt})
            secret_keys = _secret_like_keys(fn.get("environment_variables"))
            if secret_keys:
                add("ServerlessSecurityAgent", f"Serverless environment contains secret-like keys: {name}",
                    "medium", "serverless", "SERVERLESS-03 Secret Handling",
                    "Environment variables include secret-like names; plaintext env is not a secret store.",
                    "Move secrets into AWS Secrets Manager / SSM Parameter Store and reference them at runtime.",
                    {"resource": name, "secret_like_env_keys": secret_keys})
            rr = roles_by_key.get(fn.get("role"))
            if rr and _admin(rr.get("attached_policies")):
                add("ServerlessSecurityAgent", f"Serverless function has admin execution role: {name}",
                    "high", "serverless", "CIEM-01 Excessive Entitlements",
                    f"The function assumes '{rr.get('role_name') or fn.get('role')}', which has AdministratorAccess.",
                    "Scope the execution role to least privilege for the function's actual needs.",
                    {"resource": name, "role": rr.get("role_name") or fn.get("role"),
                     "attached_policies": rr.get("attached_policies")})

    # ── Load balancers / CDN (ELB/ALB/NLB/Classic + CloudFront) ──────────
    # AWS-native shape: resources.load_balancers[] with listeners[], scheme,
    # ssl_policy, waf_web_acl, access_logs. The generic _check_edge reads a flat
    # shape (top-level load_balancers with tls_min_version/waf_enabled) and finds
    # nothing here — so evaluate the AWS shape directly.
    if want("edge"):
        # ssl_policy names that still permit TLS 1.0/1.1
        _weak_lb_policies = ("2015-05", "2016-08", "tls-1-0", "tls-1-1", "fs-2018-06")
        for lb in res.get("load_balancers") or []:
            name = lb.get("name") or lb.get("arn") or "load-balancer"
            internet = str(lb.get("scheme") or "").lower() == "internet-facing"
            listeners = lb.get("listeners") or []
            if str(lb.get("type") or "").lower() == "classic":
                add("EdgeCdnSecurityAgent", f"Deprecated Classic Load Balancer: {name}", "medium",
                    "cloud_network", "CSPM-06 Network Exposure",
                    f"'{name}' is a Classic ELB — a deprecated LB type with weaker TLS/routing controls.",
                    "Migrate to an Application or Network Load Balancer.", {"resource": name, "type": "classic"})
            has_http = any(str(l.get("protocol") or "").upper() == "HTTP" for l in listeners)
            has_https = any(str(l.get("protocol") or "").upper() in ("HTTPS", "TLS") for l in listeners)
            for l in listeners:
                proto = str(l.get("protocol") or "").upper()
                if proto == "HTTP" and _falsey(l.get("redirect_to_https")) and internet:
                    add("EdgeCdnSecurityAgent", f"Load balancer serves plaintext HTTP without redirect: {name}",
                        "high", "cloud_network", "CSPM-09 Transport",
                        f"'{name}' has an internet-facing HTTP:{l.get('port', 80)} listener that does not redirect to HTTPS.",
                        "Redirect HTTP to HTTPS (or remove the HTTP listener); serve traffic over TLS only.",
                        {"resource": name, "port": l.get("port"), "redirect_to_https": False})
                pol = str(l.get("ssl_policy") or "").lower()
                if proto in ("HTTPS", "TLS") and pol and any(w in pol for w in _weak_lb_policies):
                    add("EdgeCdnSecurityAgent", f"Load balancer allows legacy TLS: {name}", "high",
                        "cloud_network", "CSPM-09 Transport",
                        f"'{name}' listener uses SSL policy '{l.get('ssl_policy')}' which permits TLS 1.0/1.1.",
                        "Use a TLS-1.2+ security policy (e.g. ELBSecurityPolicy-TLS13-1-2-2021-06).",
                        {"resource": name, "ssl_policy": l.get("ssl_policy")})
            if internet and has_http and not has_https:
                add("EdgeCdnSecurityAgent", f"Internet-facing load balancer serves only plaintext HTTP: {name}",
                    "high", "cloud_network", "CSPM-09 Transport",
                    f"'{name}' is internet-facing with no HTTPS listener — all traffic is unencrypted.",
                    "Add an HTTPS listener with a valid certificate and redirect HTTP to it.",
                    {"resource": name})
            if internet and str(lb.get("type") or "").lower() != "network" and not lb.get("waf_web_acl"):
                add("EdgeCdnSecurityAgent", f"Internet-facing load balancer has no WAF: {name}", "medium",
                    "cloud_network", "CSPM-10 Edge Protection",
                    f"'{name}' is internet-facing but has no WAF web ACL associated.",
                    "Associate an AWS WAF web ACL to filter malicious requests.",
                    {"resource": name, "waf_web_acl": None})
            if _falsey((lb.get("access_logs") or {}).get("enabled")):
                add("EdgeCdnSecurityAgent", f"Load balancer access logging disabled: {name}", "low",
                    "cloud_network", "CSPM-07 Logging",
                    f"'{name}' does not have access logging enabled.",
                    "Enable access logs to an S3 bucket for forensics.", {"resource": name})
            # internal-tagged but internet-exposed
            if internet and str((lb.get("tags") or {}).get("Internal", "")).lower() == "true":
                add("EdgeCdnSecurityAgent", f"'Internal'-tagged load balancer is internet-facing: {name}", "high",
                    "cloud_network", "CSPM-06 Network Exposure",
                    f"'{name}' is tagged Internal=true but has scheme=internet-facing — likely unintended exposure.",
                    "Make the load balancer internal, or correct the tag/exposure.",
                    {"resource": name, "tags": lb.get("tags")})
        # CloudFront distributions
        for dist in res.get("cloudfront_distributions") or []:
            dname = dist.get("id") or dist.get("domain_name") or "distribution"
            vpp = str(dist.get("viewer_protocol_policy") or "").lower()
            if vpp == "allow-all":
                add("EdgeCdnSecurityAgent", f"CloudFront allows plaintext viewer traffic: {dname}", "high",
                    "cloud_network", "CSPM-09 Transport",
                    f"CloudFront distribution '{dname}' viewer-protocol-policy is allow-all (HTTP permitted).",
                    "Set viewer-protocol-policy to redirect-to-https or https-only.", {"resource": dname})
            if _falsey(dist.get("waf_web_acl")):
                add("EdgeCdnSecurityAgent", f"CloudFront distribution has no WAF: {dname}", "medium",
                    "cloud_network", "CSPM-10 Edge Protection", f"CloudFront '{dname}' has no WAF web ACL.",
                    "Associate an AWS WAF web ACL.", {"resource": dname})
            mintls = str(dist.get("minimum_protocol_version") or "").lower()
            if mintls and ("tlsv1_2" not in mintls and "tlsv1.2" not in mintls and "tls1.2" not in mintls):
                add("EdgeCdnSecurityAgent", f"CloudFront allows legacy TLS: {dname}", "medium",
                    "cloud_network", "CSPM-09 Transport",
                    f"CloudFront '{dname}' minimum protocol version is {dist.get('minimum_protocol_version')}.",
                    "Set the minimum protocol to TLSv1.2_2021 or later.", {"resource": dname})

    return F


def _finding(
    *,
    provider: str,
    scope: str,
    agent: str,
    title: str,
    severity: str,
    category: str,
    owasp_category: str,
    description: str,
    remediation: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "category": category,
        "owasp_category": owasp_category,
        "description": description,
        "remediation": remediation,
        "evidence": _redact({
            "provider": provider,
            "scope": scope,
            "agent": agent,
            **evidence,
        }),
    }


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, entry in value.items():
            if str(key).lower().replace("-", "_") in _SECRETISH_KEYS:
                redacted[key] = "[redacted]"
            else:
                redacted[key] = _redact(entry)
        return redacted
    if isinstance(value, list):
        return [_redact(entry) for entry in value]
    return value
