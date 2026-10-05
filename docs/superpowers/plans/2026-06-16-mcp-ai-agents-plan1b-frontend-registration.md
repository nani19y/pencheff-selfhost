# MCP / AI Agents — Plan 1b: Frontend Registration

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the `mcp` target kind registerable, displayable, and editable in the web UI — the `mcp-ai-agents` card maps to `kind:"mcp"`, a source-aware `McpFormSection` collects per-source config, the consent vocabulary is mirrored client-side, and list/detail/edit pages render the new kind.

**Architecture:** Mirrors the existing per-kind FE pattern. `McpFormSection` is a new controlled component (sibling of `components/register-target/llm-form-section.tsx`). Auth secrets use the flat `credentials.headers` pattern (like `llm`/`grpc`); MCP config is sent as `kind_config` (discriminated by `kind:"mcp"`). Consent uses `getKindDisclosures` with mcp-specific conditional logic mirroring the backend `_required_disclosed_actions`.

**Tech Stack:** Next.js 15 (static export), React, TypeScript, Tailwind, `@/components/brutal` UI primitives. Verify with `cd apps/web && npx tsc --noEmit` (no FE unit tests in this area; typecheck is the gate).

**Series:** Plan 1 (backend) done. This is 1b. Plan 2/3 = scanner. Backend contract (from Plan 1) — `McpConfig` fields: `kind:"mcp"`, `source_type` ∈ {mcp_http, mcp_stdio, agent_http, agent_browser}, `url`, `transport` ∈ {sse, streamable_http}, `command: string[]`, `env`, `cwd`, `provider` (LlmProvider), `model`, `request_template`, `response_path`, `prompt_selector`, `send_selector`, `response_selector`, `tool_allowlist: string[]`, `tool_denylist: string[]`, `dynamic_invocation: bool`, `destructive_opt_in: bool`. Validation: mcp_http→url+transport; mcp_stdio→command; agent_http→provider (custom→+request_template+response_path); agent_browser→url+3 selectors; destructive_opt_in→requires dynamic_invocation; allow/deny must not overlap. Consent actions: `mcp_enumerate` (always), `mcp_tool_invocation` (when dynamic_invocation), `mcp_destructive_tool_invocation` (when destructive_opt_in).

---

## File structure

| File                                                       | Change                                                                                                                                                           |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apps/web/components/register-target/target-types.ts`      | `"mcp"` in `SupportedKind`; `mcp-ai-agents` card `kind:"mcp"`                                                                                                    |
| `apps/web/lib/consent-disclosures.ts`                      | 3 `ACTIONS` defs; `mcp` in `REQUIRED_ACTION_IDS_BY_KIND` + `ADDITIONAL_ACTIONS_BY_KIND`; `getKindDisclosures` mcp conditional; `KindConfigForDisclosures` fields |
| `apps/web/components/register-target/mcp-form-section.tsx` | **New** controlled component                                                                                                                                     |
| `apps/web/app/targets/new/page.tsx`                        | mcp state, form mount, submit branch, `renderable`                                                                                                               |
| `apps/web/app/targets/page.tsx`                            | local `SupportedKind`; `TYPE_BADGE_BY_KIND`; `COVERAGE_BADGES_BY_KIND` + styles; `effectiveKind`                                                                 |
| `apps/web/app/targets/[id]/page.tsx`                       | `SupportedKind`; `KindConfigView` mcp block                                                                                                                      |
| `apps/web/app/targets/[id]/edit/page.tsx`                  | `Kind` union; `NEW_KIND_FORM_SECTIONS`; hydrate `case "mcp"`; mcp state + submit branch (reuse McpFormSection)                                                   |

Each task ends by running `cd apps/web && npx tsc --noEmit` (expected: no errors) and committing.

---

## Task 1: Wire kind in target-types.ts + list-page display

**Files:** Modify `apps/web/components/register-target/target-types.ts`; `apps/web/app/targets/page.tsx`.

- [ ] **Step 1: target-types.ts** — add `"mcp"` to the `SupportedKind` union (after `"memory"`), and change the `mcp-ai-agents` card's `kind: "llm"` → `kind: "mcp"`.

- [ ] **Step 2: list page (`app/targets/page.tsx`)** — make the new kind render correctly:
  - Add `| "mcp"` to the local `SupportedKind` union (the drifted copy).
  - In `TYPE_BADGE_BY_KIND`, add `mcp: "MCP / AGENT",`.
  - In `COVERAGE_BADGES_BY_KIND`, add `mcp: ["MCP", "AGENT"],`.
  - In `effectiveKind`, before the final `return "url";`, add `if (k === "mcp") return "llm";` (group mcp with llm for the list's stat/filter buckets — minimal, avoids a new DisplayKind).
  - If `COVERAGE_STYLES` / the `TypeBadge` styles map don't have entries for `"MCP"` / `"AGENT"` / `"MCP / AGENT"`, add neutral entries reusing the existing llm badge style values (copy the `"LLM ENDPOINT"` / `"LLM RED TEAM"` style objects' values).

- [ ] **Step 3: Verify** — `cd apps/web && npx tsc --noEmit` → no errors.

- [ ] **Step 4: Commit**

```bash
git add apps/web/components/register-target/target-types.ts apps/web/app/targets/page.tsx
git commit -m "feat(web): map mcp-ai-agents card to kind=mcp + list-page badges"
```

---

## Task 2: Consent disclosures for mcp

**Files:** Modify `apps/web/lib/consent-disclosures.ts`.

- [ ] **Step 1: Add 3 action definitions** to the `ACTIONS` object (follow the existing entry shape `{id, displayName, description}`):

```ts
  mcp_enumerate: {
    id: "mcp_enumerate",
    displayName: "MCP enumeration & static analysis",
    description:
      "Connect to the MCP server / agent and enumerate its tools, resources, and prompts, then statically analyze the manifest (tool descriptions, schemas) for poisoning, hidden instructions, and excessive agency. No tools are invoked; no side effects.",
  },
  mcp_tool_invocation: {
    id: "mcp_tool_invocation",
    displayName: "MCP tool invocation (safe)",
    description:
      "Dynamically invoke the server's read-only / non-destructive tools with adversarial inputs to detect injection-via-tool-output, SSRF, and parameter-injection. May cause read-side effects on the target.",
  },
  mcp_destructive_tool_invocation: {
    id: "mcp_destructive_tool_invocation",
    displayName: "MCP destructive tool invocation",
    description:
      "Invoke tools classed as destructive (exec / file-write / delete / payment / network-egress) with adversarial inputs to prove impact. This can modify or destroy data on the target — only authorize against a sandbox / throwaway target you own.",
  },
```

- [ ] **Step 2: Required + additional action maps** — add to `REQUIRED_ACTION_IDS_BY_KIND`:

```ts
  mcp: ["mcp_enumerate"],
```

and to `ADDITIONAL_ACTIONS_BY_KIND`:

```ts
  mcp: ["mcp_tool_invocation", "mcp_destructive_tool_invocation"],
```

- [ ] **Step 3: Extend `KindConfigForDisclosures`** with the two mcp flags:

```ts
  /** MCP targets: dynamic-testing opt-ins that add tool-invocation disclosures. */
  dynamic_invocation?: boolean;
  destructive_opt_in?: boolean;
```

- [ ] **Step 4: Extend `getKindDisclosures`** — after the existing `k8s_cluster` Phase-B block and before `const orderedIds`, add (mirrors backend `_required_disclosed_actions`: destructive nested inside dynamic):

```ts
if (k === "mcp" && kindConfig?.dynamic_invocation) {
  ids.add("mcp_tool_invocation");
  if (kindConfig?.destructive_opt_in) {
    ids.add("mcp_destructive_tool_invocation");
  }
}
```

Note: `mcp_tool_invocation` / `mcp_destructive_tool_invocation` live in `ADDITIONAL_ACTIONS_BY_KIND` so they are NOT auto-required; only this conditional adds them. Confirm `ADDITIONAL_ACTIONS_BY_KIND` entries are NOT unconditionally merged into `ids` for mcp — if `getKindDisclosures` merges `additional` unconditionally (check the `const additional = ...; ids = new Set([...required, ...additional])` line), then DO NOT also add them in the conditional; instead leave `ADDITIONAL_ACTIONS_BY_KIND.mcp = []` and rely solely on the conditional block above. Pick whichever matches how `additional` is consumed; the invariant to preserve: with no dynamic_invocation, mcp discloses ONLY `mcp_enumerate`.

- [ ] **Step 5: Verify** — `cd apps/web && npx tsc --noEmit` → no errors.

- [ ] **Step 6: Commit**

```bash
git add apps/web/lib/consent-disclosures.ts
git commit -m "feat(web): mcp consent disclosure vocabulary (enumerate/tool/destructive)"
```

---

## Task 3: `McpFormSection` component

**Files:** Create `apps/web/components/register-target/mcp-form-section.tsx`.

**Read first:** `apps/web/components/register-target/llm-form-section.tsx` — mirror its conventions exactly (controlled flat props; `Input`/`Label` from `@/components/brutal`; raw `<textarea>`/`<select>`/`<button role="radio">`/checkbox; section card layout with the same className idioms; the auth-headers dynamic K-V grid). Do NOT invent new UI primitives or restyle.

- [ ] **Step 1: Create the component.** Props (all controlled getter/setter pairs):
  - `name, setName` (string)
  - `sourceType, setSourceType` (`"mcp_http"|"mcp_stdio"|"agent_http"|"agent_browser"`)
  - mcp_http: `url, setUrl` (string), `transport, setTransport` (`"sse"|"streamable_http"`)
  - mcp_stdio: `command, setCommand` (string — space/line entry; split to array on submit), `cwd, setCwd` (string), `envRows, setEnvRows` (K-V rows)
  - agent_http: `provider, setProvider` (LlmProvider), `model, setModel`, `requestTemplate, setRequestTemplate`, `responsePath, setResponsePath`
  - agent_browser: reuse `url, setUrl`; `promptSelector, setPromptSelector`, `sendSelector, setSendSelector`, `responseSelector, setResponseSelector`
  - common: `toolAllowlist, setToolAllowlist` (string, comma/newline), `toolDenylist, setToolDenylist` (string), `dynamicInvocation, setDynamicInvocation` (bool), `destructiveOptIn, setDestructiveOptIn` (bool), `headerRows, setHeaderRows` (auth K-V grid — copy llm's `headerRows` row type + add/remove handlers)

  Layout (each a section card mirroring llm sections):
  1. **Source type** — `<button role="radio">` card grid with the 4 source types (label + one-line description each).
  2. **Connection** — conditional on `sourceType`:
     - `mcp_http`: `Input[type=url]` for `url` + a `<select>` for `transport` (sse / streamable_http).
     - `mcp_stdio`: `<textarea>` for `command` (one token per line OR space-separated; document in helper text) + `Input` for `cwd` + env K-V grid.
     - `agent_http`: provider `<button role="radio">` grid (reuse llm's provider list) + `Input` model + (when provider==="custom") `<textarea>` requestTemplate + `Input` responsePath.
     - `agent_browser`: `Input[type=url]` url + 3 `Input`s for the selectors.
  3. **Name** — optional `Input`.
  4. **Auth headers** — the dynamic K-V grid copied from llm (Authorization / X-API-Key etc.).
  5. **Dynamic testing** — checkbox `dynamicInvocation` ("Invoke tools dynamically (read-only)"); when checked, show `toolAllowlist`/`toolDenylist` `<textarea>`s + a checkbox `destructiveOptIn` ("Allow destructive tool invocation — sandbox only"). When `dynamicInvocation` is unchecked, force `destructiveOptIn` false (disable the checkbox). Surface a small warning line under destructive.

- [ ] **Step 2: Verify** — `cd apps/web && npx tsc --noEmit` → no errors (component compiles standalone once imported in Task 4; if unused-import errors appear, they resolve in Task 4 — acceptable to commit Task 3+4 together if tsc requires the import. Otherwise mark `// eslint-disable-next-line` is NOT allowed; just sequence the commit after Task 4 wiring if needed).

- [ ] **Step 3: Commit**

```bash
git add apps/web/components/register-target/mcp-form-section.tsx
git commit -m "feat(web): McpFormSection (source-aware MCP/agent registration form)"
```

---

## Task 4: Wire McpFormSection into the new-target page

**Files:** Modify `apps/web/app/targets/new/page.tsx`.

- [ ] **Step 1: Import + state.** Import `McpFormSection`. Add `useState` vars for every McpFormSection prop (mirror the llm state block; reuse the existing `headerRows` only if it isn't already consumed by llm — if shared-state collision, create `mcpHeaderRows`). Defaults: `sourceType="mcp_http"`, `transport="sse"`, `provider="openai-chat"`, `dynamicInvocation=false`, `destructiveOptIn=false`, lists empty.

- [ ] **Step 2: `renderable`** — add `"mcp"` to the `renderable: SupportedKind[]` array.

- [ ] **Step 3: Mount the section** — alongside the other `selectedKinds.includes(...)` blocks:

```tsx
{
  selectedKinds.includes("mcp") && (
    <McpFormSection
      name={mcpName}
      setName={setMcpName}
      sourceType={mcpSourceType}
      setSourceType={setMcpSourceType}
      url={mcpUrl}
      setUrl={setMcpUrl}
      transport={mcpTransport}
      setTransport={setMcpTransport}
      command={mcpCommand}
      setCommand={setMcpCommand}
      cwd={mcpCwd}
      setCwd={setMcpCwd}
      envRows={mcpEnvRows}
      setEnvRows={setMcpEnvRows}
      provider={mcpProvider}
      setProvider={setMcpProvider}
      model={mcpModel}
      setModel={setMcpModel}
      requestTemplate={mcpRequestTemplate}
      setRequestTemplate={setMcpRequestTemplate}
      responsePath={mcpResponsePath}
      setResponsePath={setMcpResponsePath}
      promptSelector={mcpPromptSelector}
      setPromptSelector={setMcpPromptSelector}
      sendSelector={mcpSendSelector}
      setSendSelector={setMcpSendSelector}
      responseSelector={mcpResponseSelector}
      setResponseSelector={setMcpResponseSelector}
      toolAllowlist={mcpToolAllowlist}
      setToolAllowlist={setMcpToolAllowlist}
      toolDenylist={mcpToolDenylist}
      setToolDenylist={setMcpToolDenylist}
      dynamicInvocation={mcpDynamicInvocation}
      setDynamicInvocation={setMcpDynamicInvocation}
      destructiveOptIn={mcpDestructiveOptIn}
      setDestructiveOptIn={setMcpDestructiveOptIn}
      headerRows={mcpHeaderRows}
      setHeaderRows={setMcpHeaderRows}
    />
  );
}
```

- [ ] **Step 4: Submit branch** — add a `if (selectedKinds.includes("mcp")) { ... }` block (mirror the llm branch structure). Build `kind_config` from state per `source_type`, build `credentials` from `mcpHeaderRows`, validate client-side (mirror backend rules), POST:

```tsx
if (selectedKinds.includes("mcp")) {
  const st = mcpSourceType;
  // client-side validation mirroring backend McpConfig
  if (st === "mcp_http" && !mcpUrl.trim())
    throw new Error("MCP server URL is required.");
  if (st === "mcp_stdio" && !mcpCommand.trim())
    throw new Error("stdio command is required.");
  if (st === "agent_http" && !mcpProvider)
    throw new Error("Agent provider is required.");
  if (
    st === "agent_http" &&
    mcpProvider === "custom" &&
    !(mcpRequestTemplate.trim() && mcpResponsePath.trim())
  )
    throw new Error(
      "Custom provider requires request template and response path.",
    );
  if (
    st === "agent_browser" &&
    !(
      mcpUrl.trim() &&
      mcpPromptSelector.trim() &&
      mcpSendSelector.trim() &&
      mcpResponseSelector.trim()
    )
  )
    throw new Error("Browser agent requires URL and all three selectors.");
  if (mcpDestructiveOptIn && !mcpDynamicInvocation)
    throw new Error("Destructive invocation requires dynamic invocation.");

  const allow = mcpToolAllowlist
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
  const deny = mcpToolDenylist
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
  const overlap = allow.filter((a) => deny.includes(a));
  if (overlap.length)
    throw new Error(`Tool allow/deny overlap: ${overlap.join(", ")}`);

  const headers: Record<string, string> = {};
  for (const row of mcpHeaderRows) {
    const k = row.key.trim();
    const v = row.value.trim();
    if (k && v) headers[k] = v;
  }
  const env: Record<string, string> = {};
  for (const row of mcpEnvRows) {
    const k = row.key.trim();
    const v = row.value.trim();
    if (k && v) env[k] = v;
  }

  const cfg: Record<string, unknown> = { kind: "mcp", source_type: st };
  if (st === "mcp_http") {
    cfg.url = mcpUrl;
    cfg.transport = mcpTransport;
  }
  if (st === "mcp_stdio") {
    cfg.command = mcpCommand
      .split(/[\n ]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (mcpCwd.trim()) cfg.cwd = mcpCwd.trim();
    if (Object.keys(env).length) cfg.env = env;
  }
  if (st === "agent_http") {
    cfg.provider = mcpProvider;
    if (mcpModel.trim()) cfg.model = mcpModel.trim();
    if (mcpProvider === "custom") {
      cfg.request_template = mcpRequestTemplate;
      cfg.response_path = mcpResponsePath;
    }
  }
  if (st === "agent_browser") {
    cfg.url = mcpUrl;
    cfg.prompt_selector = mcpPromptSelector;
    cfg.send_selector = mcpSendSelector;
    cfg.response_selector = mcpResponseSelector;
  }
  if (allow.length) cfg.tool_allowlist = allow;
  if (deny.length) cfg.tool_denylist = deny;
  cfg.dynamic_invocation = mcpDynamicInvocation;
  cfg.destructive_opt_in = mcpDestructiveOptIn;

  const baseUrl =
    st === "mcp_http" || st === "agent_browser"
      ? mcpUrl
      : `mcp://${mcpName || st}`;
  const t = await api<{ id: string }>("/targets", {
    method: "POST",
    json: {
      name: mcpName || baseUrl,
      base_url: baseUrl,
      kind: "mcp",
      kind_config: cfg,
      disciplines: disciplinesFor("mcp"),
      ...(Object.keys(headers).length ? { credentials: { headers } } : {}),
    },
  });
  // follow the same post-create navigation/toast the llm branch uses
}
```

NOTE: if `disciplinesFor` has no `mcp` entry, add a sensible one (mirror llm's disciplines) in `lib/disciplines.ts` / wherever `disciplinesFor` is defined — check and align; if it returns `[]` for unknown kinds without erroring, that's acceptable for v1 (note as a concern).

- [ ] **Step 5: Verify** — `cd apps/web && npx tsc --noEmit` → no errors. Also run `npx next build` if feasible (static export must succeed); if build is too slow in this environment, tsc + a note is acceptable.

- [ ] **Step 6: Commit**

```bash
git add apps/web/app/targets/new/page.tsx
git commit -m "feat(web): wire McpFormSection into new-target flow (register kind=mcp)"
```

---

## Task 5: Detail view + edit page

**Files:** Modify `apps/web/app/targets/[id]/page.tsx`, `apps/web/app/targets/[id]/edit/page.tsx`.

- [ ] **Step 1: Detail page** (`[id]/page.tsx`):
  - Add `"mcp"` wherever the local `SupportedKind` / kind union is declared.
  - In `KindConfigView`, add an `{kind === "mcp" && (...)}` block rendering the salient config via the existing `<Field>` helper: source_type, url/transport (or command), provider/model (agent_http), and the dynamic/destructive flags. Example:

```tsx
{
  kind === "mcp" && (
    <>
      <Field label="Source" value={cfg.source_type as string} mono />
      {cfg.url ? (
        <Field label="URL" value={cfg.url as string} mono span={2} />
      ) : null}
      {cfg.transport ? (
        <Field label="Transport" value={cfg.transport as string} mono />
      ) : null}
      {cfg.command ? (
        <Field
          label="Command"
          value={(cfg.command as string[]).join(" ")}
          mono
          span={2}
        />
      ) : null}
      {cfg.provider ? (
        <Field label="Provider" value={cfg.provider as string} mono />
      ) : null}
      <Field
        label="Dynamic"
        value={cfg.dynamic_invocation ? "enabled" : "static only"}
        mono
      />
      {cfg.destructive_opt_in ? (
        <Field label="Destructive" value="opted in" mono />
      ) : null}
    </>
  );
}
```

- Ensure the commission-modal kind_config pass-through includes `dynamic_invocation` / `destructive_opt_in` so `getKindDisclosures` computes the right consent (check where the modal receives `kindConfig` and that it forwards these fields — they ride on `target.kind_config` already, so confirm the modal reads them).

- [ ] **Step 2: Edit page** (`[id]/edit/page.tsx`):
  - Add `"mcp"` to the `Kind` union and to `NEW_KIND_FORM_SECTIONS`.
  - Add `case "mcp": { /* hydrate mcp state from kc */ break; }` in the hydrate switch.
  - Add mcp state vars (same as new page) + render `<McpFormSection .../>` in the edit form.
  - Add an mcp branch in the submit handler building `kind_config` + `credentials.headers` (same shape as Task 4) and PATCH (use `credentials`, not `kind_credentials`).

- [ ] **Step 3: Verify** — `cd apps/web && npx tsc --noEmit` → no errors.

- [ ] **Step 4: Commit**

```bash
git add apps/web/app/targets/[id]/page.tsx apps/web/app/targets/[id]/edit/page.tsx
git commit -m "feat(web): mcp kind config view + edit-page support"
```

---

## Task 6: Build verification

- [ ] **Step 1:** `cd apps/web && npx tsc --noEmit` → no errors.
- [ ] **Step 2:** `cd apps/web && npx next build` → succeeds (static export). If it fails, fix the reported file inline. If the environment can't run next build in reasonable time, run `npx tsc --noEmit` and note the build was not run.
- [ ] **Step 3: Commit** any fixups:

```bash
git add -A apps/web && git commit -m "fix(web): mcp registration build fixups"
```

(Skip if already green.)

---

## Self-review

**Spec coverage (spec §5.3, §11):** card→kind (T1) ✓; consent vocab FE (T2) ✓; McpFormSection 4 sources (T3) ✓; new-page wiring + submit (T4) ✓; list badge (T1) ✓; detail view + edit (T5) ✓; build gate (T6) ✓.
**Placeholder scan:** deterministic files have complete code; the component (T3) is specified field-by-field with the `llm-form-section.tsx` pattern as the explicit template (implementer reads it) — acceptable for a UI component mirroring an existing one.
**Type consistency:** kind_config keys (`source_type`, `url`, `transport`, `command`, `env`, `cwd`, `provider`, `model`, `request_template`, `response_path`, `prompt_selector`, `send_selector`, `response_selector`, `tool_allowlist`, `tool_denylist`, `dynamic_invocation`, `destructive_opt_in`) match the Plan 1 `McpConfig` exactly; consent action IDs match Plan 1 backend + the FE-mirror test. Client validation mirrors backend `McpConfig` validators (incl. destructive→dynamic, allow/deny overlap, custom completeness).
**Risk note:** the `getKindDisclosures` additional-vs-conditional handling (T2 Step 4) must preserve "no dynamic ⇒ only mcp_enumerate" — implementer must verify how `ADDITIONAL_ACTIONS_BY_KIND` is consumed and pick the matching wiring.
