"""Hybrid-cluster orchestrator (feature 001-multi-target-scan-pipelines).

Drives kinds that combine static artifact analysis (Phase A) with optional
live-system probing (Phase B): cicd_pipeline, k8s_cluster.

Pipeline shape (spec §6.3):

    Phase A (always runs):
        * cicd_pipeline → audit the cloned repo via run_zizmor (GitHub Actions
          CI/CD-attack analysis: PPE / template injection / excessive
          permissions / unpinned actions / self-hosted runners), run_gitleaks
          (committed secrets), and run_checkov (Dockerfile / IaC hygiene).
        * k8s_cluster   → audit uploaded manifests via run_checkov
          (with framework="kubernetes") + run_trivy_k8s_config.

    Phase B (only when kind_credentials present):
        * cicd_pipeline → CI provider API enumeration via run_kubectl_get
          / CI-specific helpers (deferred — Phase B body lands in a
          follow-up pass once the CI-API wrappers ship).
        * k8s_cluster  → K8sReconAgent + RbacEnumAgent against kubeconfig
          (deferred — needs run_kubectl_get / run_rakkess wrappers).

Kubeconfigs / CI tokens are decrypted from Target.kind_credentials_encrypted
by the caller and materialized to /tmp/<scan_id>/.kube/config mode 0600.
That bootstrap step lives in scan_runner / repo_scan_task, not here, so
this module stays focused on the scanner-orchestration logic.

This deterministic implementation runs every Phase A scanner serially; an
LLM-orchestrated variant that decides which scanners to skip lives in a
follow-up pass.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

log = logging.getLogger("pencheff.hybrid_orchestrator")


# Per-kind Phase A scanner allowlist. Same shape as
# artifact_orchestrator.KIND_TO_ARTIFACT_TOOLS.
KIND_TO_HYBRID_PHASE_A_TOOLS: dict[str, frozenset[str]] = {
    # zizmor = CI/CD-attack analysis (PPE, template injection, excessive
    # permissions, unpinned/known-vulnerable actions, self-hosted runners);
    # gitleaks = committed secrets; checkov = Dockerfile/IaC hygiene (its
    # overlapping GitHub Actions workflow checks are filtered out below so
    # zizmor solely owns workflow analysis).
    "cicd_pipeline": frozenset({"run_checkov", "run_gitleaks", "run_zizmor", "run_gitlab_ci_audit"}),
    "k8s_cluster":   frozenset({"run_checkov", "run_trivy_config", "run_kubescape", "run_kube_linter"}),
}


_HYBRID_KINDS = frozenset({"cicd_pipeline", "k8s_cluster"})


def _has_live_phase_b(target: Any) -> bool:
    """True when this target's kind_config implies live-system probing.

    cicd_pipeline → ``live_api_enabled == True``.
    k8s_cluster   → ``target == "live_cluster"``.
    """
    kind = target.kind
    cfg = target.kind_config or {}
    if kind == "cicd_pipeline":
        return bool(cfg.get("live_api_enabled"))
    if kind == "k8s_cluster":
        return cfg.get("target") == "live_cluster"
    return False


async def run_hybrid_orchestrator(
    *,
    scan_id: str,
    target: Any,
    Session: Any,
    kind_credentials: dict | None = None,
) -> None:
    """Drive a hybrid-cluster scan (Phase A always, Phase B conditional).

    Args:
        scan_id: UUID of the Scan row.
        target: Target ORM row with ``kind_config`` + optionally
            ``kind_credentials_encrypted`` for Phase B.
        Session: AsyncSession factory.
    """
    import pencheff.server as srv
    from ...db.models import Scan
    from ...events import publish_scan_event

    kind = target.kind
    if kind not in _HYBRID_KINDS:
        raise ValueError(
            f"run_hybrid_orchestrator called with non-hybrid kind={kind!r}"
        )

    cfg = dict(target.kind_config or {})
    phase_b = _has_live_phase_b(target)
    log.info(
        "hybrid orchestrator: scan_id=%s kind=%s phase_b=%s",
        scan_id, kind, phase_b,
    )

    session_id = f"hybrid-{scan_id}"
    srv.set_kind_config_for_session(session_id, cfg)
    if kind_credentials is not None:
        srv.set_kind_credentials_for_session(session_id, kind_credentials)

    async def _log(msg: str) -> None:
        async with Session() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            log_list = list(s.log or [])
            log_list.append(msg)
            s.log = log_list[-1000:]
            await db.commit()
        publish_scan_event(scan_id, {"type": "stage_start", "label": msg[:160], "pct": None})

    try:
        # ── Phase A: artifact analysis ─────────────────────────────
        await _log(f"[Hybrid] Phase A starting for kind={kind}")

        # Acquire the manifest archive / repo via existing artifact tools.
        acquired: dict[str, Any] = {}
        if kind == "cicd_pipeline":
            if cfg.get("repo_url"):
                await _log(f"[Hybrid] cloning {cfg.get('repo_url')}")
                acquired = await srv.artifact_clone_repo(
                    session_id=session_id,
                    url=cfg.get("repo_url", ""),
                )
                if "error" in acquired:
                    from .artifact_orchestrator import _clone_error
                    raise RuntimeError(_clone_error(acquired))
        elif kind == "k8s_cluster":
            if cfg.get("manifests_archive_url"):
                await _log(f"[Hybrid] downloading manifests from {cfg.get('manifests_archive_url')}")
                acquired = await srv.artifact_download(
                    session_id=session_id,
                    url=cfg.get("manifests_archive_url", ""),
                    sha256=cfg.get("manifests_sha256", "0" * 64),
                    filename="manifests.tar.gz",
                )
                if "error" in acquired:
                    # Manifest download is optional — Phase A can still run
                    # against the empty-state if the operator only configured
                    # Phase B. Log and continue.
                    await _log(f"[Hybrid] manifests download failed: {acquired['error']}")
                    acquired = {}
                elif acquired.get("local_path"):
                    # checkov scans a directory tree, not a .tar.gz — extract the
                    # archive and point Phase A at the extracted dir. Without this
                    # checkov gets the tarball path and finds nothing.
                    import tarfile
                    import zipfile
                    from pathlib import Path

                    arc = Path(acquired["local_path"])
                    dest = arc.parent / "manifests-extracted"
                    try:
                        if tarfile.is_tarfile(arc):
                            with tarfile.open(arc) as tf:
                                tf.extractall(dest, filter="data")  # 3.12 safe filter
                        elif zipfile.is_zipfile(arc):
                            with zipfile.ZipFile(arc) as zf:
                                for m in zf.namelist():
                                    if m.startswith("/") or ".." in m:
                                        continue  # path-traversal guard
                                    zf.extract(m, dest)
                        else:
                            raise RuntimeError("archive is neither tar nor zip")
                        acquired["local_path"] = str(dest)
                        await _log("[Hybrid] extracted manifest archive for scanning")
                    except Exception as exc:  # noqa: BLE001
                        await _log(f"[Hybrid] manifest extract failed: {exc}")
                        acquired = {}

        # Run Phase A scanners.
        all_findings: list[dict[str, Any]] = []
        scanner_stats: dict[str, dict[str, Any]] = {}
        for tool_name in sorted(KIND_TO_HYBRID_PHASE_A_TOOLS[kind]):
            fn = getattr(srv, tool_name, None)
            if fn is None:
                scanner_stats[tool_name] = {"error": "tool not exposed"}
                continue
            args = _phase_a_args_for(kind, tool_name, acquired, cfg)
            if args is None:
                scanner_stats[tool_name] = {"skipped": "no input"}
                continue
            await _log(f"[Hybrid] Phase A running {tool_name}")
            try:
                result = await fn(session_id=session_id, **args)
            except Exception as exc:  # noqa: BLE001
                scanner_stats[tool_name] = {"error": str(exc)}
                continue
            if "error" in result:
                scanner_stats[tool_name] = {
                    "error": result["error"],
                    "skipped": result.get("skipped", False),
                }
                continue
            findings = result.get("findings", [])
            if kind == "cicd_pipeline" and tool_name == "run_checkov":
                # zizmor owns workflow analysis with sharper, higher-severity
                # findings; drop checkov's overlapping .github/workflows checks
                # so permissions/etc. aren't double-reported (and double-scored).
                findings = [
                    f for f in findings
                    if ".github/workflows/" not in (f.get("file_path") or "")
                ]
            scanner_stats[tool_name] = {"findings_count": len(findings), "phase": "A"}
            for f in findings:
                f["scanner"] = result.get("scanner") or tool_name
                f["phase"] = "A"
            all_findings.extend(findings)

        # ── Phase B: live-system probing (when creds present) ──────
        if phase_b:
            if kind_credentials is None:
                await _log(
                    f"[Hybrid] Phase B requested by kind_config but no "
                    f"kind_credentials bound — skipping Phase B (operator must "
                    f"set kind_credentials for live probing)."
                )
                scanner_stats["_phase_b_skipped"] = {"reason": "no kind_credentials"}
            else:
                await _log(f"[Hybrid] Phase B starting for kind={kind}")
                if kind == "k8s_cluster":
                    await _run_phase_b_k8s(
                        session_id, cfg, all_findings, scanner_stats, _log,
                    )
                elif kind == "cicd_pipeline":
                    await _run_phase_b_cicd(
                        session_id, cfg, all_findings, scanner_stats, _log,
                    )

        # Surface that live probing was available but not run, so a Phase-A-only
        # cicd report doesn't read as "complete" when it skipped secret / runner
        # / OIDC enumeration. (Phase B needs live_api_enabled + a provider token.)
        if not phase_b and kind == "cicd_pipeline":
            scanner_stats["_phase_b_available"] = {
                "ran": False,
                "reason": "live_api_enabled is off — static (Phase A) scan only.",
                "enable": "Turn on 'live-API probing' on the target and attach a "
                          "provider token to also enumerate pipeline secrets, "
                          "self-hosted runners, OIDC trust and workflow run history.",
            }

        # ── Persist + finalize ─────────────────────────────────────
        await _log(
            f"[Hybrid] {len(all_findings)} findings · phase_a_only={not phase_b}"
        )
        await _persist_hybrid_findings(scan_id, all_findings, Session)
        await _finalize_hybrid_scan(scan_id, kind, all_findings, scanner_stats, phase_b, Session)
        publish_scan_event(scan_id, {
            "type": "finished", "scan_id": scan_id,
            "total_findings": len(all_findings),
        })

    finally:
        # Best-effort kubeconfig tempfile cleanup (Phase B materialised it
        # at /tmp/<session_id>/.kube/config mode 0600; unlink regardless of
        # success path).
        try:
            from pencheff.hybrid_tools import _unlink_kubeconfig
            _unlink_kubeconfig(session_id)
        except Exception:  # noqa: BLE001
            pass
        srv.set_kind_config_for_session(session_id, None)
        srv.set_kind_credentials_for_session(session_id, None)


async def _run_phase_b_k8s(
    session_id: str,
    cfg: dict[str, Any],
    all_findings: list[dict[str, Any]],
    scanner_stats: dict[str, dict[str, Any]],
    log_fn,
) -> None:
    """Phase B for k8s_cluster: kubectl-get enumeration + rakkess RBAC audit."""
    import pencheff.server as srv

    # Resources to enumerate by default (operator can extend via kind_config
    # in a future iteration).
    resources_to_check = ["rolebindings", "clusterrolebindings", "serviceaccounts", "networkpolicies"]
    for resource in resources_to_check:
        await log_fn(f"[Hybrid] Phase B kubectl get {resource}")
        try:
            result = await srv.run_kubectl_get(session_id=session_id, resource=resource)
        except Exception as exc:  # noqa: BLE001
            scanner_stats[f"run_kubectl_get:{resource}"] = {"error": str(exc), "phase": "B"}
            continue
        if "error" in result:
            scanner_stats[f"run_kubectl_get:{resource}"] = {
                "error": result["error"], "skipped": result.get("skipped", False), "phase": "B",
            }
            continue
        findings = result.get("findings", [])
        scanner_stats[f"run_kubectl_get:{resource}"] = {"findings_count": len(findings), "phase": "B"}
        for f in findings:
            f["scanner"] = "kubectl-get"
            f["phase"] = "B"
        all_findings.extend(findings)

    if cfg.get("rbac_enum", True):
        await log_fn("[Hybrid] Phase B running rakkess")
        try:
            result = await srv.run_rakkess(session_id=session_id)
        except Exception as exc:  # noqa: BLE001
            scanner_stats["run_rakkess"] = {"error": str(exc), "phase": "B"}
            return
        if "error" in result:
            scanner_stats["run_rakkess"] = {
                "error": result["error"], "skipped": result.get("skipped", False), "phase": "B",
            }
            return
        findings = result.get("findings", [])
        scanner_stats["run_rakkess"] = {"findings_count": len(findings), "phase": "B"}
        for f in findings:
            f["scanner"] = "rakkess"
            f["phase"] = "B"
        all_findings.extend(findings)


async def _run_phase_b_cicd(
    session_id: str,
    cfg: dict[str, Any],
    all_findings: list[dict[str, Any]],
    scanner_stats: dict[str, dict[str, Any]],
    log_fn,
) -> None:
    """Phase B for cicd_pipeline: provider API enumeration.

    Supports github_actions today; other providers deferred to focused future
    sessions (gitlab_ci / jenkins / azure_pipelines / circleci API helpers).
    """
    import pencheff.server as srv
    from urllib.parse import urlparse

    provider = cfg.get("provider")
    repo_url = cfg.get("repo_url", "")
    parsed = urlparse(repo_url)
    parts = (parsed.path or "").strip("/").split("/")

    if provider == "github_actions":
        if len(parts) < 2:
            scanner_stats["run_github_actions_api"] = {
                "error": "kind_config.repo_url must be https://github.com/<owner>/<repo>",
                "phase": "B",
            }
            return
        owner, repo = parts[0], parts[1].removesuffix(".git")
        await log_fn(f"[Hybrid] Phase B GitHub Actions API: {owner}/{repo}")
        try:
            result = await srv.run_github_actions_api(session_id=session_id, owner=owner, repo=repo)
        except Exception as exc:  # noqa: BLE001
            scanner_stats["run_github_actions_api"] = {"error": str(exc), "phase": "B"}
            return
        _merge_phase_b(result, "run_github_actions_api", "github-actions-api", all_findings, scanner_stats)
        return

    if provider == "gitlab_ci":
        if len(parts) < 2:
            scanner_stats["run_gitlab_ci_api"] = {
                "error": "kind_config.repo_url must be a gitlab project URL",
                "phase": "B",
            }
            return
        # Strip ``.git`` from the last segment then re-join — supports nested
        # groups (parent/sub/project) via parts[:-1] + last-cleaned.
        last = parts[-1].removesuffix(".git")
        project = "/".join(parts[:-1] + [last])
        # Use the host from repo_url for self-hosted GitLab instances.
        gitlab_base = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else "https://gitlab.com"
        await log_fn(f"[Hybrid] Phase B GitLab CI API: {gitlab_base}/{project}")
        try:
            result = await srv.run_gitlab_ci_api(
                session_id=session_id, project=project, base_url=gitlab_base,
            )
        except Exception as exc:  # noqa: BLE001
            scanner_stats["run_gitlab_ci_api"] = {"error": str(exc), "phase": "B"}
            return
        _merge_phase_b(result, "run_gitlab_ci_api", "gitlab-ci-api", all_findings, scanner_stats)
        return

    if provider == "jenkins":
        # Jenkins kind_config.repo_url is the Jenkins controller base URL
        # (e.g. https://jenkins.example.com), not a per-job URL.
        await log_fn(f"[Hybrid] Phase B Jenkins API: {repo_url}")
        try:
            result = await srv.run_jenkins_api(session_id=session_id, base_url=repo_url)
        except Exception as exc:  # noqa: BLE001
            scanner_stats["run_jenkins_api"] = {"error": str(exc), "phase": "B"}
            return
        _merge_phase_b(result, "run_jenkins_api", "jenkins-api", all_findings, scanner_stats)
        return

    if provider == "azure_pipelines":
        # Azure DevOps URL shape: https://dev.azure.com/<org>/<project>/_git/<repo>
        # The first two path segments after the host are org + project.
        if len(parts) < 2:
            scanner_stats["run_azure_pipelines_api"] = {
                "error": "kind_config.repo_url must be a dev.azure.com URL",
                "phase": "B",
            }
            return
        organization, project = parts[0], parts[1]
        await log_fn(f"[Hybrid] Phase B Azure Pipelines API: {organization}/{project}")
        try:
            result = await srv.run_azure_pipelines_api(
                session_id=session_id, organization=organization, project=project,
            )
        except Exception as exc:  # noqa: BLE001
            scanner_stats["run_azure_pipelines_api"] = {"error": str(exc), "phase": "B"}
            return
        _merge_phase_b(result, "run_azure_pipelines_api", "azure-pipelines-api",
                       all_findings, scanner_stats)
        return

    if provider == "circleci":
        # CircleCI flow: kind_config.repo_url is the source repo URL; project_slug
        # is derived as gh/<owner>/<repo> (GitHub) or bb/<owner>/<repo> (Bitbucket).
        if len(parts) < 2:
            scanner_stats["run_circleci_api"] = {
                "error": "kind_config.repo_url must be a github.com or bitbucket.org URL",
                "phase": "B",
            }
            return
        owner, last = parts[0], parts[1].removesuffix(".git")
        host = (parsed.netloc or "").lower()
        vcs_prefix = "gh" if "github" in host else ("bb" if "bitbucket" in host else None)
        if vcs_prefix is None:
            scanner_stats["run_circleci_api"] = {
                "error": f"unsupported VCS host for circleci: {host!r}",
                "phase": "B",
            }
            return
        project_slug = f"{vcs_prefix}/{owner}/{last}"
        await log_fn(f"[Hybrid] Phase B CircleCI API: {project_slug}")
        try:
            result = await srv.run_circleci_api(session_id=session_id, project_slug=project_slug)
        except Exception as exc:  # noqa: BLE001
            scanner_stats["run_circleci_api"] = {"error": str(exc), "phase": "B"}
            return
        _merge_phase_b(result, "run_circleci_api", "circleci-api",
                       all_findings, scanner_stats)
        return

    scanner_stats["_phase_b_deferred"] = {
        "reason": f"Phase B wrappers for provider={provider!r} pending follow-up impl",
        "supported_in_v1": ["github_actions", "gitlab_ci", "jenkins", "azure_pipelines", "circleci"],
    }


def _merge_phase_b(
    result: dict[str, Any],
    stat_key: str,
    scanner_label: str,
    all_findings: list[dict[str, Any]],
    scanner_stats: dict[str, dict[str, Any]],
) -> None:
    """Common shape for Phase B result merging."""
    if "error" in result:
        scanner_stats[stat_key] = {
            "error": result["error"],
            "skipped": result.get("skipped", False),
            "phase": "B",
        }
        return
    findings = result.get("findings", [])
    scanner_stats[stat_key] = {"findings_count": len(findings), "phase": "B"}
    for f in findings:
        f["scanner"] = scanner_label
        f["phase"] = "B"
    all_findings.extend(findings)


def _phase_a_args_for(
    kind: str,
    tool_name: str,
    acquired: dict[str, Any],
    cfg: dict[str, Any],
) -> dict[str, Any] | None:
    """Per-(kind, tool) argument mapping for Phase A scanners."""
    if kind == "cicd_pipeline":
        # All three cicd Phase A scanners take the cloned repo root:
        # checkov auto-detects frameworks, gitleaks scans committed secrets,
        # zizmor discovers .github/workflows itself.
        path = acquired.get("local_path")
        if not path:
            return None
        if tool_name in ("run_checkov", "run_gitleaks", "run_zizmor", "run_gitlab_ci_audit"):
            return {"source_path": path}
    if kind == "k8s_cluster":
        # local_path is the extracted manifest dir (the acquire phase unpacks the
        # archive). checkov scans with framework=kubernetes; trivy config /
        # kubescape / kube-linter each take the dir directly.
        path = acquired.get("local_path")
        if not path:
            return None
        if tool_name == "run_checkov":
            return {"source_path": path, "framework": "kubernetes"}
        if tool_name in ("run_trivy_config", "run_kubescape", "run_kube_linter"):
            return {"source_path": path}
    return None


async def _persist_hybrid_findings(
    scan_id: str,
    findings: list[dict[str, Any]],
    Session: Any,
) -> None:
    from ...db.models import Finding as DbFinding
    if not findings:
        return
    def _clip(v, n):
        # Clamp bounded String() columns so an over-long owasp_category/cwe_id
        # can't abort the batch insert (StringDataRightTruncationError).
        return v[:n] if isinstance(v, str) and len(v) > n else v

    def _location(f: dict):
        # checkov/config scanners emit file_path + line_start; surface it as the
        # finding endpoint so grouped occurrences show "file:line", not "—".
        fp = f.get("file_path") or f.get("endpoint")
        if not fp:
            return None
        fp = str(fp)
        idx = fp.rfind("/clone/")
        if idx != -1:
            fp = fp[idx + len("/clone/"):]
        ls = f.get("line_start")
        return f"{fp}:{ls}" if ls else fp

    async with Session() as db:
        for f in findings:
            db.add(DbFinding(
                scan_id=scan_id,
                title=_clip(f.get("title") or "(untitled)", 500),
                severity=_clip(f.get("severity") or "info", 16),
                category=_clip(f.get("category") or "unknown", 64),
                owasp_category=_clip(f.get("owasp_category"), 32),
                cwe_id=_clip(f.get("cwe_id"), 32),
                endpoint=_clip(_location(f), 2048),
                description=(f.get("description") or "")[:4000],
                remediation=(f.get("remediation") or "")[:4000] or None,
                evidence=[f["evidence"]] if f.get("evidence") else None,
            ))
        await db.commit()


async def _finalize_hybrid_scan(
    scan_id: str,
    kind: str,
    findings: list[dict[str, Any]],
    scanner_stats: dict[str, dict[str, Any]],
    phase_b_attempted: bool,
    Session: Any,
) -> None:
    from types import SimpleNamespace

    from ...db.models import Scan
    from ..grader import compute as compute_grade
    score, grade, counts = compute_grade(
        [SimpleNamespace(severity=(f.get("severity") or "info"),
                         suppressed=False, verification_status=None) for f in findings],
        target_kind=kind,
    )
    async with Session() as db:
        s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        s.status = "done"
        s.progress_pct = 100
        s.current_stage = "complete"
        s.finished_at = datetime.now(timezone.utc)
        s.grade = grade
        s.score = score
        s.summary = {
            **(s.summary or {}),
            **counts,
            "kind": kind,
            "scanner_stats": scanner_stats,
            "counts": counts,
            "pipeline": "hybrid",
            "phase_a_only": not phase_b_attempted,
        }
        log_list = list(s.log or [])
        log_list.append(f"[Hybrid] complete · {len(findings)} findings · {counts}")
        s.log = log_list[-1000:]
        await db.commit()
