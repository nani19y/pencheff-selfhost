"""Regression: offline AWS CSPM (inventory JSON) must produce findings.

Before the fix, run_cloud_checks read a flat/simplified inventory shape and found
nothing in a real AWS-native export (resources.{s3_buckets,rds,ec2,iam,...}), so
an offline cloud_account scan returned 0 findings. _check_aws_inventory now
evaluates the AWS shape directly.
"""
from pencheff_api.services.agent_swarm.cloud_scanners import run_cloud_checks

AWS_INVENTORY = {
    "provider": "aws",
    "account_id": "123456789012",
    "resources": {
        "iam": {
            "root_account": {"mfa_enabled": False, "access_keys_active": True},
            "users": [{"username": "admin", "mfa_enabled": False,
                       "attached_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
                       "access_keys": [{"key_id": "AKIA...", "age_days": 540}]}],
            "password_policy": {"minimum_length": 6, "require_symbols": False},
        },
        "s3_buckets": [{"name": "public-bucket", "acl": "public-read-write",
                        "encryption": None, "versioning": "Disabled",
                        "public_access_block": {"block_public_acls": False}}],
        "rds": {"instances": [{"identifier": "db1", "publicly_accessible": True,
                               "encrypted": False, "backup_retention_days": 0}]},
        "ec2": {"security_groups": [{"group_name": "web",
                 "inbound_rules": [{"source": "0.0.0.0/0", "protocol": "tcp", "port_range": "22"},
                                   {"source": "0.0.0.0/0", "protocol": "-1", "port_range": "all"}]}]},
        "cloudtrail": {"trails": [{"name": "t", "is_multi_region": False, "log_file_validation": False}]},
        "guardduty": {"enabled": False},
    },
}


def test_offline_aws_inventory_produces_findings():
    cfg = {"provider": "aws", "kind": "cloud_account",
           "services": ["iam", "storage", "database", "edge", "audit_logging", "secrets"],
           "inventory": AWS_INVENTORY}
    findings, stats = run_cloud_checks(kind="cloud_account", cfg=cfg, kind_credentials=None)
    titles = " | ".join(f["title"] for f in findings)
    assert len(findings) >= 10, f"expected many CSPM findings, got {len(findings)}: {titles}"
    # spot-check the headline misconfigurations
    assert any("Root account MFA" in f["title"] for f in findings), titles
    assert any("publicly accessible" in f["title"].lower() and "s3" in f["title"].lower() for f in findings), titles
    assert any("RDS instance is publicly accessible" in f["title"] for f in findings), titles
    assert any("all ports" in f["title"] for f in findings), titles


def test_non_aws_native_inventory_still_supported():
    # Generic flat shape must still work (no regression for the old path).
    cfg = {"provider": "gcp", "kind": "cloud_account",
           "inventory": {"buckets": [{"name": "b", "public": True}]}}
    findings, _ = run_cloud_checks(kind="cloud_account", cfg=cfg, kind_credentials=None)
    assert any("publicly accessible" in f["title"].lower() for f in findings)


# Serverless (Lambda) AWS-native inventory: resources.lambda_functions with
# resource_policy (public invocation), deprecated runtimes, environment_variables
# (secret-like keys), and execution roles cross-referenced to resources.iam_roles.
SERVERLESS_INVENTORY = {
    "provider": "aws",
    "account_id": "123456789012",
    "resources": {
        "lambda_functions": [
            {"function_name": "payment-processor", "runtime": "python2.7",
             "role": "arn:aws:iam::123456789012:role/lambda-admin-role",
             "environment_variables": {"DB_PASSWORD": "x", "STRIPE_SECRET": "y", "ENVIRONMENT": "prod"},
             "resource_policy": {"Statement": [{"Effect": "Allow", "Principal": "*",
                                                "Action": "lambda:InvokeFunction"}]}},
            {"function_name": "data-backup", "runtime": "python3.9",
             "role": "arn:aws:iam::123456789012:role/lambda-backup-role",
             "environment_variables": {"BACKUP_BUCKET": "b"}, "resource_policy": None},
        ],
        "iam_roles": [
            {"role_name": "lambda-admin-role", "arn": "arn:aws:iam::123456789012:role/lambda-admin-role",
             "attached_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"]},
            {"role_name": "lambda-backup-role", "arn": "arn:aws:iam::123456789012:role/lambda-backup-role",
             "attached_policies": ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]},
        ],
    },
}


def test_serverless_aws_inventory_produces_findings():
    cfg = {"provider": "aws", "kind": "serverless_function", "inventory": SERVERLESS_INVENTORY}
    findings, _ = run_cloud_checks(kind="serverless_function", cfg=cfg, kind_credentials=None)
    titles = " | ".join(f["title"] for f in findings)
    assert any("public invocation: payment-processor" in f["title"] for f in findings), titles
    assert any("deprecated runtime: payment-processor" in f["title"] for f in findings), titles
    assert any("secret-like keys: payment-processor" in f["title"] for f in findings), titles
    assert any("admin execution role: payment-processor" in f["title"] for f in findings), titles
    # the clean function (supported runtime, no public policy, read-only role) has no serverless findings
    assert not any("data-backup" in f["title"] for f in findings), titles
    # a serverless scan must stay scoped to serverless — no account-wide findings
    # (e.g. "CloudTrail not enabled") inferred from a function-only inventory.
    assert not any("CloudTrail" in f["title"] for f in findings), titles
    assert all(f.get("category") == "serverless" for f in findings), titles


def test_cloud_account_still_runs_full_suite():
    # Regression guard for the kind-scoping: cloud_account must NOT be narrowed.
    cfg = {"provider": "aws", "kind": "cloud_account",
           "services": ["iam", "storage", "database", "edge", "audit_logging", "secrets"],
           "inventory": AWS_INVENTORY}
    findings, _ = run_cloud_checks(kind="cloud_account", cfg=cfg, kind_credentials=None)
    assert any("CloudTrail" in f["title"] for f in findings)


# ── Azure Function Apps + GCP Cloud Functions serverless parity ──────────────
AZURE_FUNCTIONS = {
    "provider": "azure", "subscription_id": "sub-123",
    "resources": {
        "function_apps": [
            {"name": "payment-fn", "runtime": "python|3.6", "auth_level": "anonymous",
             "app_settings": {"DB_PASSWORD": "x", "STRIPE_SECRET": "y", "ENV": "prod"},
             "identity": {"principal_id": "pid-1"}},
            {"name": "clean-fn", "runtime": "python|3.11", "auth_level": "function",
             "app_settings": {"REGION": "eastus"}, "identity": {"principal_id": "pid-2"}},
        ],
        "role_assignments": [
            {"principal_id": "pid-1", "role": "Owner"},
            {"principal_id": "pid-2", "role": "Reader"},
        ],
    },
}

GCP_FUNCTIONS = {
    "provider": "gcp", "project_id": "proj-123",
    "resources": {
        "cloud_functions": [
            {"name": "ingest-fn", "runtime": "python37",
             "environment_variables": {"API_KEY": "x", "PASSWORD": "y"},
             "iam_policy": {"bindings": [{"role": "roles/cloudfunctions.invoker", "members": ["allUsers"]}]},
             "service_account_email": "sa-1@proj.iam"},
            {"name": "clean-fn", "runtime": "python311",
             "environment_variables": {"REGION": "us"}, "service_account_email": "sa-2@proj.iam"},
        ],
        "service_accounts": [
            {"email": "sa-1@proj.iam", "roles": ["roles/owner"]},
            {"email": "sa-2@proj.iam", "roles": ["roles/logging.logWriter"]},
        ],
    },
}


def _titles(findings):
    return " | ".join(f["title"] for f in findings)


def test_azure_function_apps_produce_serverless_findings():
    cfg = {"provider": "azure", "subscription_id": "sub-123", "inventory": AZURE_FUNCTIONS}
    findings, _ = run_cloud_checks(kind="serverless_function", cfg=cfg, kind_credentials=None)
    t = _titles(findings)
    assert any("public invocation: payment-fn" in f["title"] for f in findings), t
    assert any("deprecated runtime: payment-fn" in f["title"] for f in findings), t
    assert any("secret-like keys: payment-fn" in f["title"] for f in findings), t
    assert any("over-privileged identity: payment-fn" in f["title"] for f in findings), t
    assert not any("clean-fn" in f["title"] for f in findings), t
    assert all(f.get("category") == "serverless" for f in findings), t


def test_gcp_cloud_functions_produce_serverless_findings():
    cfg = {"provider": "gcp", "project_id": "proj-123", "inventory": GCP_FUNCTIONS}
    findings, _ = run_cloud_checks(kind="serverless_function", cfg=cfg, kind_credentials=None)
    t = _titles(findings)
    assert any("public invocation: ingest-fn" in f["title"] for f in findings), t
    assert any("deprecated runtime: ingest-fn" in f["title"] for f in findings), t
    assert any("secret-like keys: ingest-fn" in f["title"] for f in findings), t
    assert any("over-privileged identity: ingest-fn" in f["title"] for f in findings), t
    assert not any("clean-fn" in f["title"] for f in findings), t


# Load balancer / CDN AWS-native inventory (resources.load_balancers with listeners,
# scheme, ssl_policy, waf_web_acl) — the generic _check_edge reads a flat shape and
# missed these, returning grade A / 0 findings on a misconfigured internet-facing ALB.
LB_INVENTORY = {
    "provider": "aws",
    "resources": {
        "load_balancers": [
            {"name": "prod-alb", "type": "application", "scheme": "internet-facing",
             "waf_web_acl": None, "access_logs": {"enabled": False},
             "listeners": [
                 {"port": 80, "protocol": "HTTP", "redirect_to_https": False},
                 {"port": 443, "protocol": "HTTPS", "ssl_policy": "ELBSecurityPolicy-2016-08"}]},
            {"name": "legacy-elb", "type": "classic", "scheme": "internet-facing",
             "waf_web_acl": None, "access_logs": {"enabled": True},
             "listeners": [{"port": 80, "protocol": "HTTP"}]},
        ],
    },
}


def test_aws_load_balancer_inventory_produces_findings():
    cfg = {"provider": "aws", "kind": "load_balancer_cdn", "inventory": LB_INVENTORY}
    findings, _ = run_cloud_checks(kind="load_balancer_cdn", cfg=cfg, kind_credentials=None)
    titles = " | ".join(f["title"] for f in findings)
    assert any("plaintext HTTP without redirect: prod-alb" in f["title"] for f in findings), titles
    assert any("allows legacy TLS: prod-alb" in f["title"] for f in findings), titles
    assert any("no WAF: prod-alb" in f["title"] for f in findings), titles
    assert any("Deprecated Classic Load Balancer: legacy-elb" in f["title"] for f in findings), titles
    # scoped to the LB/network section only
    assert all(f.get("category") == "cloud_network" for f in findings), titles


def test_standalone_secrets_manager_inventory_detected():
    # A secrets_manager-only AWS-native inventory (no s3/rds) must still trigger
    # the AWS-native evaluator — previously _is_aws_native missed it → 0 findings.
    inv = {"provider": "aws", "resources": {
        "secrets_manager": {"secrets": [{"name": "prod/db", "rotation_enabled": False}]},
        "kms": {"keys": [{"key_id": "k1", "rotation_enabled": False}]}}}
    findings, _ = run_cloud_checks(kind="secrets_manager",
                                   cfg={"provider": "aws", "inventory": inv}, kind_credentials=None)
    assert any("rotation disabled" in f["title"].lower() for f in findings), \
        " | ".join(f["title"] for f in findings)


# ── cloud_database native shape (resources.{rds_instances,dynamodb_tables,
#    elasticache_clusters}) — previously grade A / 0 findings ────────────────
CLOUD_DB_INVENTORY = {
    "provider": "aws",
    "account_id": "123456789012",
    "resources": {
        "rds_instances": [
            {"identifier": "prod-mysql-primary", "engine": "mysql",
             "publicly_accessible": True, "storage_encrypted": False, "encrypted": False,
             "backup_retention_days": 0, "deletion_protection": False,
             "iam_authentication": False, "tags": {"DataClass": "confidential"}},
            # Well-configured → must produce NOTHING.
            {"identifier": "prod-aurora-cluster", "engine": "aurora-mysql",
             "publicly_accessible": False, "storage_encrypted": True, "encrypted": True,
             "backup_retention_days": 7, "deletion_protection": True,
             "iam_authentication": True},
        ],
        "dynamodb_tables": [
            {"name": "payment-records", "encryption": {"type": "DEFAULT", "enabled": False},
             "point_in_time_recovery": False, "deletion_protection": False,
             "tags": {"DataClass": "pci"}},
            # KMS-encrypted, PITR + deletion protection → must produce NOTHING.
            {"name": "audit-logs", "encryption": {"type": "KMS", "enabled": True},
             "point_in_time_recovery": True, "deletion_protection": True},
        ],
        "elasticache_clusters": [
            {"cluster_id": "prod-redis-cache", "engine": "redis",
             "at_rest_encryption": False, "in_transit_encryption": False,
             "auth_token_enabled": False},
        ],
    },
}


def test_cloud_database_native_inventory_produces_findings():
    cfg = {"provider": "aws", "kind": "cloud_database", "inventory": CLOUD_DB_INVENTORY}
    findings, _ = run_cloud_checks(kind="cloud_database", cfg=cfg, kind_credentials=None)
    titles = " | ".join(f["title"] for f in findings)

    # Was 0 findings / grade A before the fix.
    assert findings, "cloud_database native inventory must produce findings"
    # Public + unencrypted prod DB → critical.
    assert any(f["severity"] == "critical" and "prod-mysql-primary" in f["title"] for f in findings)
    assert "not encrypted at rest: prod-mysql-primary" in titles
    assert "RDS backups disabled: prod-mysql-primary" in titles
    # PCI DynamoDB unencrypted → high; Redis with no AUTH → high.
    assert any(f["severity"] == "high" and "payment-records" in f["title"] for f in findings)
    assert any("Redis AUTH token disabled" in f["title"] for f in findings)
    assert any("ElastiCache at-rest encryption disabled" in f["title"] for f in findings)

    # Discrimination: well-configured resources must NOT be flagged.
    assert "aurora" not in titles.lower()
    assert "audit-logs" not in titles


def test_cloud_database_all_secure_produces_nothing():
    inv = {"provider": "aws", "resources": {"rds_instances": [
        {"identifier": "ok", "publicly_accessible": False, "storage_encrypted": True,
         "backup_retention_days": 7, "deletion_protection": True, "iam_authentication": True}]}}
    cfg = {"provider": "aws", "kind": "cloud_database", "inventory": inv}
    findings, _ = run_cloud_checks(kind="cloud_database", cfg=cfg, kind_credentials=None)
    assert findings == []


# ── secrets_manager native shape — enriched beyond rotation-only ────────────
SECRETS_INVENTORY = {
    "provider": "aws",
    "account_id": "123456789012",
    "resources": {
        "secrets_manager": {"secrets": [
            {"name": "prod/db/master-password", "rotation_enabled": False,
             "last_rotated_days": 412, "kms_key_id": None, "recovery_window_days": 0,
             "resource_policy": {"Statement": [{"Effect": "Allow", "Principal": "*",
                                                "Action": "secretsmanager:GetSecretValue"}]},
             "tags": {"DataClass": "confidential"}},
            {"name": "prod/stripe/api-key", "rotation_enabled": False, "last_rotated_days": 999,
             "kms_key_id": None, "recovery_window_days": 7,
             "cross_account_principals": ["arn:aws:iam::999888777666:root"],
             "tags": {"DataClass": "pci"}},
            # Well-configured → NOTHING.
            {"name": "prod/app/session-key", "rotation_enabled": True, "last_rotated_days": 15,
             "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/prod-cmk",
             "recovery_window_days": 30,
             "resource_policy": {"Statement": [{"Effect": "Allow",
                 "Principal": {"AWS": "arn:aws:iam::123456789012:role/app"},
                 "Action": "secretsmanager:GetSecretValue"}]}},
        ]},
        "kms": {"keys": [
            {"key_id": "key/legacy", "rotation_enabled": False,
             "policy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "kms:*"}]}},
            {"key_id": "key/prod-cmk", "rotation_enabled": True},
        ]},
    },
}


def test_secrets_manager_native_inventory_enriched_findings():
    cfg = {"provider": "aws", "kind": "secrets_manager", "inventory": SECRETS_INVENTORY}
    findings, _ = run_cloud_checks(kind="secrets_manager", cfg=cfg, kind_credentials=None)
    titles = " | ".join(f["title"] for f in findings)

    assert any(f["severity"] == "critical" and "resource policy is public" in f["title"]
               and "master-password" in f["title"] for f in findings)
    assert any(f["severity"] == "critical" and "KMS key policy is public" in f["title"] for f in findings)
    assert "Secret shared cross-account: prod/stripe/api-key" in titles
    assert any("not encrypted with a customer-managed key: prod/db/master-password" in f["title"] for f in findings)
    assert "Secret deletion has no recovery window: prod/db/master-password" in titles
    # Sensitive + stale rotation escalates to high.
    assert any(f["severity"] == "high" and "rotation disabled: prod/stripe/api-key" in f["title"]
               for f in findings)
    # Discrimination: the well-configured secret + KMS key produce nothing.
    assert "session-key" not in titles
    assert "prod-cmk" not in titles


def test_secrets_manager_all_secure_produces_nothing():
    inv = {"provider": "aws", "account_id": "123456789012", "resources": {
        "secrets_manager": {"secrets": [{"name": "ok", "rotation_enabled": True,
            "last_rotated_days": 10, "kms_key_id": "arn:...:key/cmk", "recovery_window_days": 30}]},
        "kms": {"keys": [{"key_id": "k", "rotation_enabled": True}]}}}
    cfg = {"provider": "aws", "kind": "secrets_manager", "inventory": inv}
    findings, _ = run_cloud_checks(kind="secrets_manager", cfg=cfg, kind_credentials=None)
    assert findings == []


def test_secrets_manager_flat_secrets_manager_secrets_shape():
    # The offline export uses resources.secrets_manager_secrets (flat list) with
    # age_days / last_rotated_date rather than the nested secrets_manager.secrets
    # + last_rotated_days shape. Was grade A / 0 findings before the fix.
    inv = {"provider": "aws", "account_id": "123456789012", "resources": {
        "secrets_manager_secrets": [
            {"name": "prod/db/master", "rotation_enabled": False, "last_rotated_date": None,
             "kms_key_id": None, "age_days": 900,
             "resource_policy": {"Statement": [{"Effect": "Allow", "Principal": "*",
                                                "Action": "secretsmanager:GetSecretValue"}]},
             "tags": {"DataClass": "confidential"}},
            # Well-configured → NOTHING.
            {"name": "prod/db/replica", "rotation_enabled": True, "last_rotated_date": "2024-06-01",
             "kms_key_id": "arn:...:key/cmk", "age_days": 60,
             "resource_policy": {"Statement": [{"Effect": "Allow",
                 "Principal": {"AWS": "arn:aws:iam::123456789012:role/r"},
                 "Action": "secretsmanager:GetSecretValue"}]}},
        ],
    }}
    cfg = {"provider": "aws", "kind": "secrets_manager", "inventory": inv}
    findings, _ = run_cloud_checks(kind="secrets_manager", cfg=cfg, kind_credentials=None)
    titles = " | ".join(f["title"] for f in findings)
    assert any(f["severity"] == "critical" and "resource policy is public" in f["title"] for f in findings)
    # never-rotated + confidential escalates to high.
    assert any(f["severity"] == "high" and "rotation disabled: prod/db/master" in f["title"] for f in findings)
    assert "not encrypted with a customer-managed key: prod/db/master" in titles
    # Discrimination: fully-configured secret produces nothing.
    assert "replica" not in titles
