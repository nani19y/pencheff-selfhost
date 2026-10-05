# Discipline-driven target registration — design

**Status:** approved 2026-05-21 (user direct choices)

## Problem

Operators today think in disciplines (KSPM, ASPM, AI-SPM, …), not in target-kinds. The current Step 1 of `/targets/new` forces them to translate "I want KSPM coverage" into "select Kubernetes Cluster + tune the RBAC + network-policy checkboxes." That gap costs the most when an operator's mental model maps to multiple kinds (CWPP → container image + k8s + host; ASPM → web app + REST API + source code).

We want a discipline picker that:
1. Auto-selects the underlying target kinds in Step 1.
2. Stores the chosen discipline(s) on each resulting Target row.
3. Influences the scan-time profile so that, e.g., a Target tagged KSPM scans with RBAC + network-policy enumeration on by default, and an `llm` Target tagged AI-SPM gets a guardrails-emphasising scan profile.

## Scope (v1)

Eight disciplines, all backed by already-active target kinds:

| Discipline    | Underlying kinds                          | Scan-time effect |
|---------------|-------------------------------------------|------------------|
| `kspm`        | `k8s_cluster`                             | force `rbac_enum=true`, `network_policy_audit=true` on the target's kind_config at registration |
| `kiem`        | `k8s_cluster`                             | force `rbac_enum=true`; widen namespace listing default; rakkess emphasised |
| `cwpp`        | `container_image`, `k8s_cluster`, `host`  | (target selection only — no scan-time delta in v1) |
| `aspm`        | `web_app`, `rest_api`, `source_code`      | (target selection only — no scan-time delta in v1) |
| `api_security`| `rest_api`, `graphql`                     | (target selection only) |
| `ai_redteam`  | `llm`                                     | ensure `llm_config.redteam.strategies` defaults include aggressive set (`jailbreak`, `crescendo`, `base64`, `leetspeak`); seed `datasets` with `harmbench` if blank |
| `ai_spm`      | `llm`                                     | ensure `llm_config.redteam.guardrails` defaults include `pii`, `secrets`, `unsafe-code`, `tool-authz` |
| `sbom_analysis`| `sbom`                                   | (target selection only) |

**Non-goals (v1):**
- No new target kinds. Coming-soon kinds (cloud_account, secrets_manager, …) remain coming-soon.
- No discipline-aware scan dashboard yet (will surface the badge per Target only).
- No discipline-aware reports/scoring rollups.
- No multi-discipline scan profile composition across cross-kind targets (each Target's scan stays scoped to its own kind).

## Data model

### Pydantic (`schemas/targets.py`)

```python
Discipline = Literal[
    "kspm", "kiem", "cwpp",
    "aspm", "api_security",
    "ai_redteam", "ai_spm",
    "sbom_analysis",
]

# Mapping enforced server-side: each discipline lists the kinds it's
# allowed to attach to. A Target's disciplines must all be compatible
# with its kind.
DISCIPLINE_TO_KINDS: dict[str, frozenset[str]] = {
    "kspm":          frozenset({"k8s_cluster"}),
    "kiem":          frozenset({"k8s_cluster"}),
    "cwpp":          frozenset({"container_image", "k8s_cluster", "host"}),
    "aspm":          frozenset({"web_app", "rest_api", "source_code"}),
    "api_security":  frozenset({"rest_api", "graphql"}),
    "ai_redteam":    frozenset({"llm"}),
    "ai_spm":        frozenset({"llm"}),
    "sbom_analysis": frozenset({"sbom"}),
}
```

`TargetCreate`, `TargetUpdate`, `TargetOut` each get a `disciplines: list[Discipline]` field defaulting to `[]`. A `model_validator` on TargetCreate enforces that every discipline's allowed-kinds set contains `self.kind`.

### DB (`models.py` + alembic 0048)

```python
disciplines: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
```

Migration `0048_target_disciplines.py`: `op.add_column("targets", sa.Column("disciplines", sa.ARRAY(sa.String()), nullable=True))`. Default `NULL` (treated as empty). Down-migration drops the column.

No index on `disciplines` in v1 — list pages still filter by `kind`. A GIN index can come later if discipline-scoped views materialise.

### Router (`routers/targets.py`)

- `POST /targets`: persist `body.disciplines` into the new column when present.
- `PATCH /targets/{id}`: accept `disciplines` as a list (omit → unchanged; `[]` → clear; non-empty → replace).
- `GET /targets/{id}` and list endpoints: return `disciplines` (or `[]` when NULL).

## UI

### Step 1 — tabbed picker (`components/register-target/`)

Add a tab toggle at the top of `Step1TypeSelector`: `By Discipline` (default) / `By Target Type`. State lifted to the same component; both tabs operate on the existing `selectedIds: Set<string>` so the rest of the flow doesn't change.

New file `disciplines.ts` exports:
```ts
export type DisciplineId = "kspm" | "kiem" | "cwpp" | "aspm"
  | "api_security" | "ai_redteam" | "ai_spm" | "sbom_analysis";

export type Discipline = {
  id: DisciplineId;
  label: string;          // "KSPM"
  longLabel: string;      // "Kubernetes Security Posture Management"
  description: string;    // 1-line hint
  // Target-type-card IDs (from target-types.ts) that this discipline fans out to.
  // Selecting the discipline ticks these in selectedIds.
  typeIds: string[];
};

export const DISCIPLINES: Discipline[] = [/* … */];
```

A new `<DisciplineSection>` renders the cards in a grid grouped by family (AI, CNAPP, AppSec/API, SBOM). Selecting a discipline:
1. Adds its `typeIds` to `selectedIds` (union, not replace — so picking KSPM then CWPP correctly keeps k8s_cluster as the shared dependency).
2. Adds the discipline ID to a new `selectedDisciplines: Set<DisciplineId>` Set.

Unticking a discipline removes the discipline ID but only removes its typeIds *if* no other selected discipline still needs them.

When the user flips to "By Target Type", they see what got fanned out and can hand-tune. When they flip back, the discipline cards reflect the current selection ("partially selected" state for disciplines whose typeIds are partially checked).

### Step 2 submission

`new/page.tsx` keeps the existing per-kind submit loop. Each `POST /targets` body now passes `disciplines: <filtered list>` — only the disciplines whose `DISCIPLINE_TO_KINDS` includes this row's kind. The same filter applies to edit (`[id]/edit/page.tsx`).

When a discipline triggers a scan-time default (`kspm` → `rbac_enum`/`network_policy_audit`), the FE applies the override to the kind_config payload at submission time, so even if the operator unticked the boxes the discipline wins. The scan worker re-asserts this on read for defence-in-depth.

### Step 2 — already correct

The existing per-kind form sections (k8s-cluster-form-section, container-image-form-section, etc.) require no changes; the discipline is metadata layered on top, not a new kind.

## Scan-time effects

Two layers:

1. **Registration-time defaults** (FE + BE both apply):
   - KSPM/KIEM on k8s_cluster: `rbac_enum=true`, `network_policy_audit=true`.
   - KIEM on k8s_cluster: in addition, append `"clusterroles"` and `"clusterrolebindings"` to default namespaces enumeration if not already covered — actually those resource types are already in the kubectl allowlist, so this is documentation-only.
   - AI Red Teaming on llm: ensure `llm_config.redteam.strategies` contains `["jailbreak", "crescendo", "base64", "leetspeak"]` (merge-union); seed `llm_config.redteam.datasets` with `["harmbench"]` if absent.
   - AI-SPM on llm: ensure `llm_config.redteam.guardrails` contains `["pii", "secrets", "unsafe-code", "tool-authz"]` (merge-union).

2. **Scan-runtime adjustments** (scan_runner reads `target.disciplines`):
   - On k8s_cluster scans where `"kspm" in disciplines or "kiem" in disciplines`: log a `phase_b_required=true` hint so the hybrid orchestrator emits an explicit error if no kind_credentials are bound (instead of the current "Phase B skipped" soft-pass).
   - On llm scans where `"ai_redteam" in disciplines`: bypass the `--quick` profile cap on dataset sizes (existing `redteam.budget` budget caps still apply).
   - On llm scans where `"ai_spm" in disciplines`: prefer the guardrails-only scan path (skip the full red-team battery; surface only guardrail-related findings).

Most v1 effects live at registration time. The runtime adjustments are minimal so we don't bloat scan-runner branching; the discipline column is mainly metadata + a future-proof hook.

## Migrations + back-compat

- Existing Target rows have `disciplines = NULL`. Reads return `[]`. Behaviour unchanged.
- Existing tests that don't pass `disciplines` continue to work (defaulted to `[]`).
- The `Discipline` enum is additive; reading older payloads is a no-op.

## Testing

- Schema validator tests:
  - Allowed: `kspm` on `k8s_cluster`, `aspm` on `web_app`/`rest_api`/`source_code`, etc.
  - Rejected: `kspm` on `web_app`, `ai_redteam` on `k8s_cluster`, unknown discipline string.
- Router smoke tests:
  - POST with disciplines → row persists.
  - PATCH with `disciplines=None` (omit) → unchanged. `disciplines=[]` → cleared. `disciplines=["kspm"]` → replaced.
  - GET returns disciplines.
- Migration test (alembic upgrade + downgrade round-trip in CI).
- Scan-time registration-defaults unit tests:
  - KSPM Target with kind_config rbac_enum=false at submission → stored with rbac_enum=true.
  - AI Red Teaming Target → strategies and datasets merged with aggressive defaults.

## Out of scope (future work)

- Discipline-aware dashboard widgets (e.g. "Your KSPM posture").
- Compliance mapping (SOC2 ↔ KSPM, PCI ↔ ASPM).
- Discipline-level reports (single PDF rolling up findings across all targets in a discipline).
- A discipline-aware scan trigger ("Run KSPM scans across all KSPM-tagged targets").
