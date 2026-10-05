"""Global configuration, constants, and mappings."""

from enum import Enum

# CVSS v3.1 severity thresholds
CVSS_SEVERITY = {
    "NONE": (0.0, 0.0),
    "LOW": (0.1, 3.9),
    "MEDIUM": (4.0, 6.9),
    "HIGH": (7.0, 8.9),
    "CRITICAL": (9.0, 10.0),
}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VerificationStatus(str, Enum):
    UNVERIFIED = "unverified"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    TRUE_NEGATIVE = "true_negative"
    FALSE_NEGATIVE = "false_negative"


class TestDepth(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


# OWASP Top 10 2021 mapping
OWASP_TOP_10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# OWASP LLM Top 10 (2025) mapping. Used by the llm_red_team modules to
# tag findings; rendered in the UI alongside the OWASP Top 10 / OWASP
# Mobile labels. Keys match the LLM01..LLM10 IDs the OWASP project ships.
OWASP_LLM_TOP_10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# AI security / governance mappings for OWASP LLM findings. These are
# intentionally category-level mappings: concrete implementation
# evidence still lives on each Finding.
MITRE_ATLAS_MAP = {
    "LLM01": ["AML.T0051", "AML.T0054"],
    "LLM02": ["AML.T0057", "AML.T0024"],
    "LLM03": ["AML.T0010", "AML.T0016"],
    "LLM04": ["AML.T0020", "AML.T0054"],
    "LLM05": ["AML.T0051", "AML.T0048"],
    "LLM06": ["AML.T0040", "AML.T0054"],
    "LLM07": ["AML.T0057", "AML.T0058"],
    "LLM08": ["AML.T0057", "AML.T0024"],
    "LLM09": ["AML.T0046", "AML.T0054"],
    "LLM10": ["AML.T0029", "AML.T0034"],
}

NIST_AI_RMF_MAP = {
    "LLM01": ["MAP 1.5", "MEASURE 2.7", "MANAGE 2.3"],
    "LLM02": ["MAP 2.3", "MEASURE 2.8", "MANAGE 4.1"],
    "LLM03": ["MAP 3.4", "MEASURE 2.5", "MANAGE 3.2"],
    "LLM04": ["MAP 4.1", "MEASURE 2.6", "MANAGE 2.4"],
    "LLM05": ["MEASURE 2.7", "MANAGE 2.3"],
    "LLM06": ["MAP 3.2", "MEASURE 2.8", "MANAGE 2.3"],
    "LLM07": ["MAP 2.3", "MEASURE 2.8", "MANAGE 4.1"],
    "LLM08": ["MAP 4.1", "MEASURE 2.6", "MANAGE 4.1"],
    "LLM09": ["MEASURE 2.9", "MANAGE 1.3"],
    "LLM10": ["MEASURE 2.12", "MANAGE 2.4"],
}

EU_AI_ACT_MAP = {
    "LLM01": ["Article 15", "Article 55"],
    "LLM02": ["Article 10", "Article 15", "Article 55"],
    "LLM03": ["Article 17", "Article 55"],
    "LLM04": ["Article 10", "Article 15"],
    "LLM05": ["Article 15", "Article 50"],
    "LLM06": ["Article 14", "Article 15"],
    "LLM07": ["Article 13", "Article 15", "Article 55"],
    "LLM08": ["Article 10", "Article 15"],
    "LLM09": ["Article 13", "Article 50"],
    "LLM10": ["Article 15"],
}

# GDPR (Regulation (EU) 2016/679) article references most directly
# implicated by each OWASP-LLM failure mode. Best-effort category-level
# mapping for the report — not legal advice; concrete obligations still
# depend on the specific data flows of the deployed system. Article
# numbers refer to the consolidated text on EUR-Lex.
GDPR_LLM_MAP = {
    "LLM01": ["Art. 5(1)(f) Integrity and Confidentiality", "Art. 32 Security of Processing"],
    "LLM02": ["Art. 5(1)(a) Lawfulness, Fairness, Transparency", "Art. 5(1)(c) Data Minimisation", "Art. 9 Special Categories", "Art. 32 Security of Processing", "Art. 33 Breach Notification", "Art. 34 Communication of Breach"],
    "LLM03": ["Art. 28 Processor", "Art. 32 Security of Processing", "Art. 35 DPIA"],
    "LLM04": ["Art. 5(1)(d) Accuracy", "Art. 32 Security of Processing", "Art. 35 DPIA"],
    "LLM05": ["Art. 5(1)(f) Integrity and Confidentiality", "Art. 32 Security of Processing"],
    "LLM06": ["Art. 22 Automated Decision-Making", "Art. 25 Data Protection by Design", "Art. 32 Security of Processing"],
    "LLM07": ["Art. 5(1)(a) Lawfulness, Fairness, Transparency", "Art. 32 Security of Processing"],
    "LLM08": ["Art. 5(1)(c) Data Minimisation", "Art. 32 Security of Processing"],
    "LLM09": ["Art. 5(1)(d) Accuracy", "Art. 22 Automated Decision-Making"],
    "LLM10": ["Art. 32 Security of Processing"],
}

# ISO/IEC 42001:2023 (Information technology — Artificial intelligence
# — Management system) Annex A control references most directly
# implicated by each OWASP-LLM failure mode. Best-effort category-level
# mapping; the standard itself is the authoritative source for control
# wording.
ISO_42001_LLM_MAP = {
    "LLM01": ["A.6.2.4 Verification and Validation", "A.6.2.6 Operation and Monitoring", "A.8.2 System Information for Users"],
    "LLM02": ["A.7.2 Data Quality for AI Systems", "A.7.5 Data Preparation", "A.6.2.6 Operation and Monitoring"],
    "LLM03": ["A.10.3 Supplier Relationships", "A.6.2.7 Technical Documentation"],
    "LLM04": ["A.7.3 Data Acquisition", "A.7.5 Data Preparation", "A.6.2.4 Verification and Validation"],
    "LLM05": ["A.6.2.4 Verification and Validation", "A.6.2.6 Operation and Monitoring", "A.8.4 Communication of Incidents"],
    "LLM06": ["A.6.2.5 Deployment", "A.9.2 Processes for Responsible Use", "A.10.2 Allocating Responsibilities"],
    "LLM07": ["A.6.2.7 Technical Documentation", "A.8.2 System Information for Users"],
    "LLM08": ["A.7.2 Data Quality for AI Systems", "A.6.2.4 Verification and Validation"],
    "LLM09": ["A.7.2 Data Quality for AI Systems", "A.6.2.4 Verification and Validation", "A.8.2 System Information for Users"],
    "LLM10": ["A.6.2.6 Operation and Monitoring", "A.6.2.8 Recording of Event Logs"],
}

# OWASP Mobile Top 10 2024 mapping
OWASP_MOBILE_TOP_10 = {
    "M1": "Improper Credential Usage",
    "M2": "Inadequate Supply Chain Security",
    "M3": "Insecure Authentication/Authorization",
    "M4": "Insufficient Input/Output Validation",
    "M5": "Insecure Communication",
    "M6": "Inadequate Privacy Controls",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}

# PCI-DSS requirement mapping for common vulnerability categories
PCI_DSS_MAP = {
    "injection": ["6.5.1"],
    "xss": ["6.5.7"],
    "auth": ["6.5.10", "8.1", "8.2"],
    "authz": ["6.5.8", "7.1", "7.2"],
    "crypto": ["4.1", "6.5.3"],
    "misconfiguration": ["2.2", "6.2"],
    "ssrf": ["6.5.1"],
    "file_handling": ["6.5.1", "6.5.8"],
    "deserialization": ["6.5.1"],
    "smuggling": ["6.5.10"],
    "cache_poisoning": ["6.5.10"],
    "mfa_bypass": ["8.3"],
    "oauth": ["6.5.10"],
    "subdomain_takeover": ["6.5.8"],
    "waf_bypass": ["6.6"],
    "prototype_pollution": ["6.5.1"],
    "ldap": ["6.5.1"],
    "open_redirect": ["6.5.10"],
    "header_injection": ["6.5.1"],
    "websocket": ["6.5.10"],
    "mass_assignment": ["6.5.1", "6.5.8"],
    "mobile_misconfig": ["2.2", "6.2"],
    "mobile_secrets": ["3.4", "6.5.3", "6.5.10"],
    "mobile_crypto": ["3.4", "4.1", "6.5.3"],
    "mobile_storage": ["3.4", "3.5"],
    "mobile_communication": ["4.1", "4.2"],
    "mobile_binary": ["6.2", "6.5.10"],
}

# NIST 800-53 mapping
NIST_MAP = {
    "injection": ["SI-10", "SI-16"],
    "xss": ["SI-10"],
    "auth": ["IA-2", "IA-5", "IA-8"],
    "authz": ["AC-3", "AC-6"],
    "crypto": ["SC-8", "SC-12", "SC-13"],
    "misconfiguration": ["CM-6", "CM-7"],
    "ssrf": ["SI-10", "SC-7"],
    "logging": ["AU-2", "AU-3", "AU-6"],
    "deserialization": ["SI-10", "SI-16"],
    "smuggling": ["SC-7", "SI-10"],
    "cache_poisoning": ["SC-7"],
    "mfa_bypass": ["IA-2", "IA-11"],
    "oauth": ["IA-2", "IA-8"],
    "subdomain_takeover": ["CM-8", "SC-20"],
    "waf_bypass": ["SC-7", "SI-4"],
    "prototype_pollution": ["SI-10"],
    "ldap": ["SI-10", "AC-3"],
    "open_redirect": ["SI-10"],
    "header_injection": ["SI-10", "SC-7"],
    "websocket": ["SC-8", "SC-23"],
    "mass_assignment": ["AC-3", "AC-6"],
    "mobile_misconfig": ["CM-6", "CM-7"],
    "mobile_secrets": ["IA-5", "SC-12", "SC-13"],
    "mobile_crypto": ["SC-13", "SC-12", "SC-28"],
    "mobile_storage": ["SC-28", "MP-4"],
    "mobile_communication": ["SC-8", "SC-23"],
    "mobile_binary": ["SI-7", "CM-6"],
}

# SOC 2 Trust Services Criteria mapping
SOC2_MAP = {
    "injection": ["CC6.1", "CC6.6"],
    "xss": ["CC6.1", "CC6.6"],
    "auth": ["CC6.1", "CC6.2", "CC6.3"],
    "authz": ["CC6.1", "CC6.3"],
    "crypto": ["CC6.1", "CC6.7"],
    "misconfiguration": ["CC6.1", "CC7.1"],
    "ssrf": ["CC6.1", "CC6.6"],
    "logging": ["CC7.2", "CC7.3"],
    "deserialization": ["CC6.1", "CC6.6"],
    "mfa_bypass": ["CC6.1", "CC6.2"],
    "oauth": ["CC6.1", "CC6.3"],
    "subdomain_takeover": ["CC6.1", "CC9.2"],
    "cloud": ["CC6.1", "CC6.6", "A1.1"],
    "file_handling": ["CC6.1", "CC6.6"],
    "mass_assignment": ["CC6.1", "CC6.3"],
    "mobile_misconfig": ["CC6.1", "CC7.1"],
    "mobile_secrets": ["CC6.1", "CC6.7"],
    "mobile_crypto": ["CC6.1", "CC6.7"],
    "mobile_storage": ["CC6.1", "CC6.7"],
    "mobile_communication": ["CC6.1", "CC6.7"],
    "mobile_binary": ["CC6.1", "CC7.1"],
}

# ISO 27001:2022 Annex A control mapping
ISO27001_MAP = {
    "injection": ["A.8.24", "A.8.28"],
    "xss": ["A.8.28"],
    "auth": ["A.5.15", "A.8.2", "A.5.16"],
    "authz": ["A.5.15", "A.5.18"],
    "crypto": ["A.8.24", "A.8.7"],
    "misconfiguration": ["A.8.8", "A.8.9"],
    "ssrf": ["A.8.22", "A.8.28"],
    "logging": ["A.8.15", "A.8.16"],
    "deserialization": ["A.8.28"],
    "smuggling": ["A.8.22", "A.8.28"],
    "mfa_bypass": ["A.5.17", "A.8.2"],
    "oauth": ["A.5.15", "A.8.2"],
    "subdomain_takeover": ["A.8.22", "A.5.19"],
    "cloud": ["A.8.23", "A.5.19"],
    "file_handling": ["A.8.28", "A.8.22"],
    "mass_assignment": ["A.5.18", "A.8.28"],
    "waf_bypass": ["A.8.22", "A.8.28"],
    "mobile_misconfig": ["A.8.8", "A.8.9"],
    "mobile_secrets": ["A.8.24", "A.5.17"],
    "mobile_crypto": ["A.8.24", "A.8.7"],
    "mobile_storage": ["A.8.10", "A.8.12"],
    "mobile_communication": ["A.8.24", "A.8.20"],
    "mobile_binary": ["A.8.28", "A.8.9"],
}

# HIPAA Security Rule mapping
HIPAA_MAP = {
    "injection": ["164.312(a)(2)(iv)", "164.312(c)(1)"],
    "xss": ["164.312(a)(2)(iv)", "164.312(c)(1)"],
    "auth": ["164.312(a)(2)(i)", "164.312(d)"],
    "authz": ["164.312(a)(1)", "164.308(a)(4)"],
    "crypto": ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
    "misconfiguration": ["164.312(a)(1)", "164.308(a)(1)"],
    "ssrf": ["164.312(c)(1)", "164.312(e)(1)"],
    "logging": ["164.312(b)", "164.308(a)(1)(ii)(D)"],
    "deserialization": ["164.312(c)(1)", "164.312(a)(2)(iv)"],
    "mfa_bypass": ["164.312(d)", "164.312(a)(2)(i)"],
    "cloud": ["164.312(c)(1)", "164.308(a)(7)"],
    "file_handling": ["164.312(c)(1)", "164.312(a)(2)(iv)"],
    "mass_assignment": ["164.312(a)(1)", "164.308(a)(4)"],
    "mobile_misconfig": ["164.312(a)(1)", "164.308(a)(1)"],
    "mobile_secrets": ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
    "mobile_crypto": ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
    "mobile_storage": ["164.312(a)(2)(iv)", "164.312(c)(1)"],
    "mobile_communication": ["164.312(e)(1)", "164.312(e)(2)(ii)"],
    "mobile_binary": ["164.312(c)(1)", "164.308(a)(1)"],
}

# ─── Scan Profiles ────────────────────────────────────────────────────

SCAN_PROFILES: dict[str, dict] = {
    "quick": {
        "description": "Fast surface-level scan — recon + top injection checks + auth. ~5 min.",
        "modules": ["recon_passive", "recon_active", "scan_waf", "scan_pulse", "scan_injection", "scan_auth"],
        "depth": "quick",
        "crawl_depth": 1,
        "max_pages": 20,
    },
    "standard": {
        "description": "Balanced scan covering OWASP Top 10. ~15 min.",
        "modules": [
            "recon_passive", "recon_active", "recon_api_discovery",
            "scan_waf", "scan_injection", "scan_client_side",
            "scan_auth", "scan_authz", "scan_infrastructure",
            "scan_api", "scan_business_logic", "scan_pulse",
            "exploit_chain_suggest", "generate_report",
        ],
        "depth": "standard",
        "crawl_depth": 3,
        "max_pages": 100,
    },
    "deep": {
        "description": "Exhaustive pentest — all modules + advanced attacks. ~45 min+.",
        "modules": [
            "recon_passive", "recon_active", "recon_api_discovery",
            "scan_waf", "scan_injection", "scan_client_side",
            "scan_auth", "scan_mfa_bypass", "scan_oauth", "scan_authz",
            "scan_infrastructure", "scan_api", "scan_business_logic",
            "scan_cloud", "scan_file_handling", "scan_advanced", "scan_pulse",
            "scan_websocket", "scan_subdomain_takeover",
            "exploit_chain_suggest", "generate_report",
        ],
        "depth": "deep",
        "crawl_depth": 5,
        "max_pages": 500,
    },
    "api-only": {
        "description": "REST/GraphQL API security — no browser crawl, auth + injection + IDOR.",
        "modules": [
            "recon_api_discovery", "scan_waf",
            "scan_injection", "scan_auth", "scan_authz",
            "scan_api", "scan_business_logic", "scan_pulse",
            "exploit_chain_suggest", "generate_report",
        ],
        "depth": "standard",
        "crawl_depth": 0,
        "max_pages": 0,
    },
    "compliance": {
        "description": "Compliance-focused scan mapped to PCI-DSS, NIST, SOC 2, ISO 27001.",
        "modules": [
            "recon_passive", "recon_active",
            "scan_infrastructure", "scan_injection", "scan_client_side",
            "scan_auth", "scan_authz", "scan_cloud", "scan_pulse",
            "generate_report",
        ],
        "depth": "standard",
        "crawl_depth": 2,
        "max_pages": 50,
        "compliance_frameworks": ["owasp", "pci-dss", "nist", "soc2", "iso27001"],
    },
    "cicd": {
        "description": "Lightweight CI/CD gate — fast, non-destructive, fail on critical/high.",
        "modules": [
            "recon_active", "scan_waf", "scan_injection",
            "scan_auth", "scan_infrastructure", "scan_pulse",
        ],
        "depth": "quick",
        "crawl_depth": 1,
        "max_pages": 10,
        "fail_on": "high",
    },
    "sca": {
        "description": "Software Composition Analysis — deps + SBOM + license workflow.",
        "modules": ["scan_dependencies", "generate_sbom", "check_licenses"],
        "depth": "standard",
        "crawl_depth": 0,
        "max_pages": 0,
    },
    "iac": {
        "description": "Infrastructure-as-Code scan — Dockerfile + Kubernetes + Terraform.",
        "modules": ["scan_dockerfile", "scan_kubernetes", "scan_terraform"],
        "depth": "standard",
        "crawl_depth": 0,
        "max_pages": 0,
    },
    "supply-chain": {
        "description": "Full supply-chain coverage — SCA + IaC + container image.",
        "modules": [
            "scan_dependencies", "generate_sbom", "check_licenses",
            "scan_dockerfile", "scan_kubernetes", "scan_terraform",
            "scan_container_image",
        ],
        "depth": "standard",
        "crawl_depth": 0,
        "max_pages": 0,
    },
    "network-va": {
        "description": "Host + service CVE scan (no web DAST modules).",
        "modules": ["scan_host_vulns", "scan_network_misconfig"],
        "depth": "standard",
        "crawl_depth": 0,
        "max_pages": 0,
    },
    "mobile-static": {
        "description": "Static analysis of an APK or IPA — manifest, secrets, crypto, plist (no device required).",
        "modules": ["scan_mobile_static", "generate_report"],
        "depth": "standard",
        "crawl_depth": 0,
        "max_pages": 0,
    },
    "continuous": {
        "description": "Lightweight recurring scan suitable for nightly cron. ~5 min.",
        "modules": [
            "recon_active", "scan_waf", "scan_infrastructure",
            "scan_injection", "scan_auth", "scan_pulse",
        ],
        "depth": "quick",
        "crawl_depth": 1,
        "max_pages": 20,
    },
    "asm": {
        "description": "Attack Surface Management — subdomain enumeration + asset diff.",
        "modules": ["asm_discover", "asm_diff"],
        "depth": "quick",
        "crawl_depth": 0,
        "max_pages": 0,
    },
    "hackme": {
        "description": (
            "Attack Simulation — aggressive data-extraction mode. Recon everything, probe "
            "every endpoint, try every known default credential + debug path, "
            "dump whatever the target is willing to hand over. Use only against "
            "targets you own or have written authorisation to test."
        ),
        "modules": [
            "recon_passive", "recon_active", "recon_api_discovery",
            "scan_waf",
            "scan_infrastructure",
            "scan_injection",
            "scan_client_side",
            "scan_auth", "scan_mfa_bypass", "scan_oauth",
            "scan_authz",
            "scan_api", "scan_business_logic",
            "scan_advanced", "scan_pulse",
            "scan_cloud", "scan_file_handling",
            "scan_websocket", "scan_subdomain_takeover",
            "exploit_chain_suggest",
        ],
        "depth": "deep",
        "crawl_depth": 5,
        "max_pages": 300,
    },
    # ── Phase-5 deterministic profiles (no LLM in the loop) ─────────────
    "auto-quick": {
        "description": "Deterministic auto-pentest. Stealth tier; ≤ 10 min budget.",
        "modules": [],  # driven by pencheff.workflows.auto_pentest
        "depth": "quick",
        "deterministic": True,
        "tool_budget": 30,
        "request_budget": 200,
        "time_budget_seconds": 600,
        "intensity": "stealth",
    },
    "auto-standard": {
        "description": "Deterministic auto-pentest. Default tier; ≤ 45 min budget.",
        "modules": [],
        "depth": "standard",
        "deterministic": True,
        "tool_budget": 80,
        "request_budget": 2000,
        "time_budget_seconds": 2700,
        "intensity": "default",
    },
    "auto-deep": {
        "description": "Deterministic auto-pentest. Aggressive tier; ≤ 4 h budget.",
        "modules": [],
        "depth": "deep",
        "deterministic": True,
        "tool_budget": 200,
        "request_budget": 20_000,
        "time_budget_seconds": 14_400,
        "intensity": "aggressive",
    },
    "ctf-solver": {
        "description": "Deterministic CTF auto-solver — no host or scope required.",
        "modules": [],
        "depth": "standard",
        "deterministic": True,
        "tool_budget": 20,
        "request_budget": 0,
        "time_budget_seconds": 600,
    },
    "bug-bounty": {
        "description": "Deterministic bug-bounty workflow — surface enum + scan + triage.",
        "modules": [],
        "depth": "standard",
        "deterministic": True,
        "tool_budget": 60,
        "request_budget": 5000,
        "time_budget_seconds": 1800,
        "intensity": "default",
    },
    "compliance-full": {
        "description": "All-compliance scan: DAST + SCA + IaC with every framework mapping.",
        "modules": [
            "recon_active", "scan_waf", "scan_injection", "scan_client_side",
            "scan_auth", "scan_authz", "scan_infrastructure", "scan_api",
            "scan_cloud", "scan_pulse", "scan_dependencies", "generate_sbom", "check_licenses",
            "scan_dockerfile", "scan_kubernetes", "scan_terraform",
            "generate_report",
        ],
        "depth": "standard",
        "crawl_depth": 2,
        "max_pages": 50,
        "compliance_frameworks": ["owasp", "pci-dss", "nist", "soc2", "iso27001", "hipaa"],
    },
}


# ─── Tool allowlist additions for new scan areas ──────────────────────
# Existing allowlist is enforced by core.tool_runner; extend it with the SCA/IaC/network tools.
EXTRA_ALLOWED_TOOLS: list[str] = [
    "syft", "grype", "trivy", "checkov", "hadolint", "tfsec", "kubesec",
    "osv-scanner", "cyclonedx-cli", "dependency-check",
    "helm", "mitmdump", "mitmproxy",
]


# Map SCA / IaC / network categories onto compliance frameworks.
PCI_DSS_MAP.setdefault("components", ["6.2"])
PCI_DSS_MAP.setdefault("misconfiguration", PCI_DSS_MAP.get("misconfiguration", ["2.2", "6.2"]))
NIST_MAP.setdefault("components", ["SA-10", "SA-11", "SI-2"])
SOC2_MAP.setdefault("components", ["CC7.1", "CC8.1"])
ISO27001_MAP.setdefault("components", ["A.8.8", "A.8.19"])
HIPAA_MAP.setdefault("components", ["164.308(a)(8)", "164.308(a)(1)(ii)(B)"])

# Default timeouts
DEFAULT_REQUEST_TIMEOUT = 30.0
DEFAULT_SCAN_TIMEOUT = 300.0
MAX_REQUESTS_PER_SECOND = 10
MAX_CRAWL_DEPTH = 5
MAX_RESPONSE_SIZE = 1024 * 1024 * 5  # 5MB

# Common ports
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 27017,
]

TOP_1000_PORTS = list(range(1, 1001)) + [
    1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 3306, 3389,
    5432, 5900, 5985, 5986, 6379, 8080, 8443, 8888, 9090, 9200,
    9300, 11211, 27017, 27018, 50000,
]
