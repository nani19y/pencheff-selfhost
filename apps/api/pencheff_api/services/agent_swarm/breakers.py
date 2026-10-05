"""BreakerSpec table + seed_breaker_session.

The 10 breaker agents and their mandates live here. seed_breaker_session
spins up a fresh isolated pencheff session per breaker and imports the
snapshot's surface so the breaker doesn't have to re-crawl.
"""
from __future__ import annotations

from dataclasses import dataclass

import pencheff.server as pencheff_server

from ...config import get_settings
from .agent_loop import Agent
from .prompts import build_breaker_prompt
from .snapshot import ReconSnapshot
from .tools import breaker_tools_for


@dataclass(frozen=True)
class BreakerSpec:
    name: str
    mandate_one_liner: str


BREAKER_SPECS: tuple[BreakerSpec, ...] = (
    BreakerSpec("InjectionAgent",
        "Surface SQLi/NoSQLi/XXE/SSTI/cmdi + path traversal + file upload flaws."),
    BreakerSpec("ClientSideAgent",
        "Surface reflected/DOM XSS, CSRF, open redirect, and CORS misconfig."),
    BreakerSpec("AuthAgent",
        "Surface authentication weaknesses: brute-force, JWT confusion, OAuth, MFA bypass."),
    BreakerSpec("AuthzAgent",
        "Surface authorisation flaws: IDOR, vertical/horizontal privilege escalation."),
    BreakerSpec("APIAgent",
        "Surface API/GraphQL weaknesses, websocket flaws, business-logic abuse."),
    BreakerSpec("InfraAgent",
        "Surface TLS/header weaknesses, smuggling, CRLF, subdomain takeover, exposed infra."),
    BreakerSpec("CloudAgent",
        "Surface cloud misconfig: public buckets, IAM metadata, blind SSRF callbacks."),
    BreakerSpec("LLMRedTeamAgent",
        "Surface AI/LLM endpoint weaknesses: prompt injection, jailbreaks, "
        "system-prompt extraction, training-data leakage. Probe any chat / "
        "completion / embedding endpoints discovered during recon."),
    BreakerSpec("SupplyChainAgent",
        "Surface exposed dependency manifests (package.json, composer.lock, "
        "Gemfile.lock, requirements.txt), .git/.npmrc leaks, and outdated "
        "client-side JS/CSS libraries fetched from CDN or self-hosted."),
    BreakerSpec("K8sAgent",
        "Surface Kubernetes control-plane exposure: kubelet/etcd ports, "
        "anonymous-auth dashboards, exposed Prometheus/metrics endpoints, "
        "and RBAC misconfiguration signals reachable from the public surface."),
    BreakerSpec("ActiveDirectoryAgent",
        "Surface Active Directory weaknesses: Kerberoasting, AS-REP roasting, "
        "certificate template abuse (ESC1-8), unconstrained delegation, "
        "AdminSDHolder misuse, and password spray against domain services. "
        "Use scan_active_directory with BloodHound + Certipy modules."),
    BreakerSpec("MobileAppAgent",
        "Surface mobile application weaknesses: hardcoded secrets in APK/IPA, "
        "insecure data storage, exported components, weak cryptography, "
        "and certificate pinning bypass opportunities. "
        "Use scan_mobile_app with MobSF + manifest analysis."),
    BreakerSpec("ThreatModelAgent",
        "Read the recon snapshot and identify the highest-impact STRIDE "
        "categories for this target (Spoofing / Tampering / Repudiation / "
        "Information Disclosure / Denial of Service / Elevation of Privilege). "
        "Call get_findings to see what other breakers found, project that "
        "back onto the STRIDE matrix, and emit ONE INFO-severity finding "
        "summarising the threats per asset, the categories with the most "
        "real evidence, and the recommended hardening priorities. Do not "
        "fire scanners — your job is the lens, not the probe. The "
        "deterministic STRIDE/DREAD generator on the engagement is your "
        "starting point; supplement it with what the snapshot actually shows."),
    # Feature 001 — new DAST-cluster specialists for kinds that the existing
    # 13 breakers can't cover: graphql-cop/inql for GraphQL fuzzing, grpcurl
    # reflection for gRPC enumeration. Wired into KIND_TO_BREAKER_NAMES below.
    BreakerSpec("GraphQLFuzzAgent",
        "Surface GraphQL-specific weaknesses: introspection exposure, alias "
        "attacks, batched-query DoS, query-depth/complexity DoS, directive "
        "injection, field-suggestion information leak. Use run_graphql_cop "
        "and run_inql against the operator-supplied endpoint or schema_sdl."),
    BreakerSpec("GrpcReflectionAgent",
        "Surface gRPC weaknesses: missing TLS, reflection over plaintext, "
        "unauthenticated method exposure, primitive payload fuzzing on each "
        "discovered method. Use run_grpcurl (reflection or operator-supplied "
        ".proto files) and parse_proto. NEVER pass --plaintext or "
        "--import-path freely — both are blocked by _DANGEROUS_ARG_SUBSTRINGS."),
    # Feature 001 — artifact-cluster specialists (called from
    # artifact_orchestrator.py, not the DAST swarm fan-out).
    BreakerSpec("ArtifactReconAgent",
        "Catalog a static artifact (source repo / container image / IaC tree / "
        "SBOM): file tree, manifests, layers, languages, dependencies. Emit "
        "an ArtifactSnapshot for the ScannerOrchestratorAgent. Read-only — "
        "do not invoke security scanners; that is the next agent's job."),
    BreakerSpec("ScannerOrchestratorAgent",
        "Given an ArtifactSnapshot + per-kind scanner allowlist, sequence "
        "scanner invocations to maximise coverage with minimum redundancy. "
        "Tools are kind-specific: source_code gets SAST + secrets, "
        "container_image gets trivy + syft + grype, iac gets checkov + tfsec, "
        "sbom gets grype-sbom + osv-scanner-sbom, package_registry gets "
        "ecosystem-specific dep audit. Tag every finding with owasp_category."),
    # Feature 001 — hybrid-cluster specialists (Phase A + optional Phase B,
    # called from hybrid_orchestrator.py).
    BreakerSpec("CicdConfigAuditAgent",
        "Audit CI/CD pipeline configuration (GitHub Actions, GitLab CI, "
        "Jenkins, Azure Pipelines, CircleCI) for untrusted PR triggers, "
        "secret leakage to logs, missing approval gates, runner pool "
        "exposure, and outdated/pinned action references. Phase A only "
        "unless kind_credentials carries a provider token."),
    BreakerSpec("K8sManifestAuditAgent",
        "Audit Kubernetes manifests (uploaded as tarball: Helm chart, "
        "Kustomize overlays, raw YAML) for security misconfigurations: "
        "privileged containers, hostNetwork, missing securityContext, "
        "permissive PodSecurityPolicy / PodSecurityStandards, RBAC bindings "
        "to default service accounts. Use run_checkov + run_trivy_k8s_config."),
    BreakerSpec("K8sReconAgent",
        "Enumerate a live Kubernetes cluster via kubeconfig: namespaces, "
        "deployments, services, exposed ingress, network policies. Phase B "
        "of the hybrid orchestrator — requires kind_credentials.kubeconfig. "
        "Use run_kubectl_get + run_kubectl_describe."),
    BreakerSpec("RbacEnumAgent",
        "Enumerate effective RBAC permissions in a live K8s cluster using "
        "run_rakkess. Flag overly-broad bindings (cluster-admin to default "
        "ServiceAccount, wildcard verbs, escalate-to-admin paths). Phase B "
        "only — requires kind_credentials.kubeconfig."),
)


# ============================================================================
# Feature 001 — kind → breaker roster filter for the DAST cluster.
#
# Used by ``_build_breakers(profile, snapshot, kind)`` to filter BREAKER_SPECS
# to the subset relevant to this Target.kind. The artifact-cluster and
# hybrid-cluster agents (ArtifactRecon, ScannerOrchestrator, CicdConfigAudit,
# K8sManifestAudit, K8sRecon, RbacEnum) are dispatched from their own
# orchestrator modules and are NOT in this map.
#
# kind="llm" deliberately omitted — llm kinds short-circuit to the existing
# single-stage _run_llm_scan path per AC-0.3 (spec §6.5).
# ============================================================================
KIND_TO_BREAKER_NAMES: dict[str, frozenset[str]] = {
    # Legacy url — full 13-breaker roster (preserved; not actually consulted
    # since url scans take the existing path, but kept for completeness +
    # forward-compat).
    "url": frozenset({
        "InjectionAgent", "ClientSideAgent", "AuthAgent", "AuthzAgent",
        "APIAgent", "InfraAgent", "CloudAgent", "LLMRedTeamAgent",
        "SupplyChainAgent", "K8sAgent", "ActiveDirectoryAgent",
        "MobileAppAgent", "ThreatModelAgent",
    }),
    "web_app": frozenset({
        "InjectionAgent", "ClientSideAgent", "AuthAgent", "AuthzAgent",
        "APIAgent", "InfraAgent", "CloudAgent", "SupplyChainAgent",
        "ThreatModelAgent",
    }),
    "rest_api": frozenset({
        "InjectionAgent", "AuthAgent", "AuthzAgent", "APIAgent",
        "InfraAgent", "ThreatModelAgent",
    }),
    "graphql": frozenset({
        "InjectionAgent", "AuthAgent", "AuthzAgent",
        "GraphQLFuzzAgent", "APIAgent", "ThreatModelAgent",
    }),
    "websocket": frozenset({
        "InjectionAgent", "AuthAgent", "AuthzAgent",
        "APIAgent", "ThreatModelAgent",
    }),
    "grpc": frozenset({
        "InjectionAgent", "AuthAgent", "AuthzAgent",
        "GrpcReflectionAgent", "ThreatModelAgent",
    }),
}


def _breaker_budget(profile: str) -> int:
    s = get_settings()
    return {
        "quick": s.swarm_turns_breaker_quick,
        "standard": s.swarm_turns_breaker_standard,
        "deep": s.swarm_turns_breaker_deep,
    }.get(profile, s.swarm_turns_breaker_standard)


# The 13 original DAST breakers (pre-feature-001). Used as the default
# roster for callers that don't pass a ``kind`` arg (existing url scans).
# Feature 001's new BreakerSpecs (GraphQLFuzzAgent, GrpcReflectionAgent,
# ArtifactReconAgent, ScannerOrchestratorAgent, CicdConfigAuditAgent,
# K8sManifestAuditAgent, K8sReconAgent, RbacEnumAgent) are dispatched by
# their own orchestrator modules / kind filter, NOT by the legacy default.
_LEGACY_DAST_BREAKER_NAMES: frozenset[str] = frozenset({
    "InjectionAgent", "ClientSideAgent", "AuthAgent", "AuthzAgent",
    "APIAgent", "InfraAgent", "CloudAgent", "LLMRedTeamAgent",
    "SupplyChainAgent", "K8sAgent", "ActiveDirectoryAgent",
    "MobileAppAgent", "ThreatModelAgent",
})


def _build_breakers(
    *,
    profile: str,
    snapshot: ReconSnapshot,
    kind: str | None = None,
    prior_context: str | None = None,
) -> list[tuple[BreakerSpec, Agent]]:
    """Build (spec, Agent) pairs for the parallel fan-out.

    When ``kind`` is provided AND in KIND_TO_BREAKER_NAMES (feature 001
    DAST-cluster path), filter BREAKER_SPECS to that kind's roster. When
    ``kind`` is omitted (legacy callers) OR unknown, fall back to the
    original 13-breaker roster — backward-compat. The new feature-001
    BreakerSpecs (artifact/hybrid agents) are NEVER spawned by this path;
    they're dispatched from their dedicated orchestrator modules.
    """
    if kind is not None and kind in KIND_TO_BREAKER_NAMES:
        allowed = KIND_TO_BREAKER_NAMES[kind]
    else:
        allowed = _LEGACY_DAST_BREAKER_NAMES
    specs = tuple(s for s in BREAKER_SPECS if s.name in allowed)
    out: list[tuple[BreakerSpec, Agent]] = []
    for spec in specs:
        agent = Agent(
            name=spec.name,
            system_prompt=build_breaker_prompt(
                agent_name=spec.name,
                mandate_one_liner=spec.mandate_one_liner,
                prior_context=prior_context,
            ),
            tools=breaker_tools_for(profile=profile, breaker_name=spec.name),
            max_turns=_breaker_budget(profile),
            # Block ``finish`` until exploit_finding has been called on every
            # non-suppressed finding in this breaker's session (verification
            # status must leave ``unverified``).
            require_per_finding_exploit=True,
            # Signature probes the breaker MUST run — a post-loop backstop in
            # agent_loop runs any the model skipped. GraphQLFuzzAgent otherwise
            # finishes on get_findings→finish and introspection never fires.
            mandate_tools=_BREAKER_MANDATE_TOOLS.get(spec.name, frozenset()),
        )
        out.append((spec, agent))
    return out


# Breakers whose signature probe must run even if the model forgets to call it.
# Only the tools actually in the breaker's allocation (tools.py) belong here.
_BREAKER_MANDATE_TOOLS: dict[str, frozenset[str]] = {
    "GraphQLFuzzAgent": frozenset({"run_graphql_cop", "run_inql"}),
    # gRPC reflection/enumeration is the signature probe; parse_proto covers the
    # reflection-disabled (uploaded .proto) path. The backstop runs whichever the
    # model skipped — the inapplicable one returns a harmless error, logged only.
    "GrpcReflectionAgent": frozenset({"run_grpcurl", "parse_proto"}),
}


async def seed_breaker_session(snapshot: ReconSnapshot) -> str:
    """Create a fresh pencheff session for one breaker, seeded from the snapshot."""
    init = await pencheff_server.pentest_init(target_url=snapshot.target_base_url)
    sid = init["session_id"]

    # Re-apply the operator's transport/protocol config on this fresh session so
    # the protocol tools (run_grpcurl plaintext/tls, run_graphql_cop introspection,
    # …) read it via _kind_config_for_session — otherwise they default-fail (e.g.
    # grpcurl attempts TLS against a plaintext h2c endpoint).
    if snapshot.kind_config:
        set_cfg = getattr(pencheff_server, "set_kind_config_for_session", None)
        if set_cfg:
            set_cfg(sid, {**dict(snapshot.kind_config), "base_url": snapshot.target_base_url})

    if snapshot.endpoints:
        await pencheff_server.import_endpoints(
            session_id=sid,
            endpoints=[
                {
                    "url": ep.url,
                    "method": ep.method,
                    "status": ep.status,
                    "content_type": ep.content_type,
                    "parameters": list(ep.parameters),
                }
                for ep in snapshot.endpoints
            ],
        )

    if snapshot.authenticated:
        await pencheff_server.set_auth_state(
            session_id=sid,
            cookies=list(snapshot.auth_cookies),
            tokens=dict(snapshot.auth_tokens),
        )

    if snapshot.oast_session_handle:
        await pencheff_server.attach_oast(
            session_id=sid, handle=snapshot.oast_session_handle,
        )

    return sid
