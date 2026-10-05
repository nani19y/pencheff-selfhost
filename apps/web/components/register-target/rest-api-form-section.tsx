"use client";

import { Input, Label } from "@/components/brutal";

export type RestApiSpecFormat = "openapi3" | "swagger2" | "postman" | "auto";

export type RestApiConfig = {
  kind: "rest_api";
  api_spec?: Record<string, unknown> | null;
  api_spec_url?: string;
  api_spec_format: RestApiSpecFormat;
  auth_in_spec: boolean;
};

export const DEFAULT_REST_API_CONFIG: RestApiConfig = {
  kind: "rest_api",
  api_spec: null,
  api_spec_url: "",
  api_spec_format: "auto",
  auth_in_spec: true,
};

export type RestApiCredentials = {
  username: string;
  password: string;
  api_key: string;
  token: string;
  cookie: string;
};

export const EMPTY_REST_API_CREDS: RestApiCredentials = {
  username: "", password: "", api_key: "", token: "", cookie: "",
};

const FORMATS: Array<{ id: RestApiSpecFormat; label: string; hint: string }> = [
  { id: "auto", label: "Auto-detect", hint: "Parse media type from the response." },
  { id: "openapi3", label: "OpenAPI 3.x", hint: "Modern JSON/YAML spec." },
  { id: "swagger2", label: "Swagger 2.0", hint: "Legacy spec format." },
  { id: "postman", label: "Postman v2.1", hint: "Postman collection JSON." },
];

export function RestApiFormSection({
  value,
  onChange,
  name,
  setName,
  baseUrl,
  setBaseUrl,
  rawSpec,
  setRawSpec,
  creds,
  setCreds,
}: {
  value: RestApiConfig;
  onChange: (v: RestApiConfig) => void;
  name: string;
  setName: (v: string) => void;
  baseUrl: string;
  setBaseUrl: (v: string) => void;
  /** Raw textarea content. Parsed into ``value.api_spec`` on each keystroke. */
  rawSpec: string;
  setRawSpec: (v: string) => void;
  creds: RestApiCredentials;
  setCreds: (v: RestApiCredentials) => void;
}) {
  function onRawSpecChange(raw: string) {
    setRawSpec(raw);
    if (!raw.trim()) {
      onChange({ ...value, api_spec: null });
      return;
    }
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        onChange({ ...value, api_spec: parsed as Record<string, unknown> });
      }
    } catch {
      // Keep last-known-good api_spec; the parent will validate on submit.
    }
  }

  async function onSpecUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 8 * 1024 * 1024) {
      alert("Spec file must be ≤ 8 MiB.");
      return;
    }
    const text = await file.text();
    onRawSpecChange(text);
  }

  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">R1</span>
          <h2 className="font-display text-[18px] text-ink">REST API</h2>
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>API base URL</Label>
            <Input
              required
              type="url"
              placeholder="https://api.example.com/v1"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
            />
          </div>
          <div className="md:col-span-2">
            <Label>Name (optional)</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Payments API v1" />
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">R2</span>
          <h2 className="font-display text-[18px] text-ink">API spec</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-4">
          Provide an OpenAPI / Swagger / Postman spec so the scanner discovers every endpoint, parameter,
          and example payload. Without a spec, only crawled endpoints are tested.
        </p>

        <div className="grid sm:grid-cols-2 gap-5 mb-5">
          <div className="sm:col-span-2">
            <Label>Spec URL (optional)</Label>
            <Input
              type="url"
              placeholder="https://api.example.com/openapi.json"
              value={value.api_spec_url ?? ""}
              onChange={(e) => onChange({ ...value, api_spec_url: e.target.value })}
            />
          </div>
        </div>

        <div className="mb-3">
          <Label>Or paste / upload spec JSON</Label>
          <textarea
            rows={10}
            value={rawSpec}
            onChange={(e) => onRawSpecChange(e.target.value)}
            placeholder='{ "openapi": "3.0.0", "info": {…}, "paths": {…} }'
            className="w-full font-mono text-[11px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
          />
          <div className="mt-3 flex items-center gap-3">
            <input
              type="file"
              accept=".json,.yaml,.yml"
              onChange={onSpecUpload}
              className="font-mono text-[11px] text-slate"
            />
            <span className="font-mono text-[11px] text-mist">≤ 8 MiB</span>
          </div>
        </div>

        <div className="grid sm:grid-cols-4 gap-3 mt-5" role="radiogroup" aria-label="Spec format">
          {FORMATS.map((f) => {
            const active = value.api_spec_format === f.id;
            return (
              <button
                key={f.id}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => onChange({ ...value, api_spec_format: f.id })}
                className={
                  "text-left border rounded-sm p-3 transition-colors " +
                  (active ? "border-ink bg-vellum" : "border-hairline bg-paper hover:border-ink")
                }
              >
                <span className="block font-mono text-[12px] text-ink">{f.label}</span>
                <span className="mt-1 block font-mono text-[11px] text-mist">{f.hint}</span>
              </button>
            );
          })}
        </div>

        <label className="mt-5 flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={value.auth_in_spec}
            onChange={(e) => onChange({ ...value, auth_in_spec: e.target.checked })}
            className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
          />
          <span className="font-body text-[13px] text-ink">
            Auth lives inside the spec (security schemes / examples) — skip the manual auth fields below
          </span>
        </label>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">R3</span>
          <h2 className="font-display text-[18px] text-ink">Manual auth (optional)</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-6">
          Used when the spec does not carry credentials. Fernet-encrypted at rest.
        </p>
        <div className="grid sm:grid-cols-2 gap-5">
          <div>
            <Label>Username</Label>
            <Input value={creds.username} onChange={(e) => setCreds({ ...creds, username: e.target.value })} autoComplete="off" />
          </div>
          <div>
            <Label>Password</Label>
            <Input type="password" value={creds.password} onChange={(e) => setCreds({ ...creds, password: e.target.value })} autoComplete="off" />
          </div>
          <div>
            <Label>API key</Label>
            <Input value={creds.api_key} onChange={(e) => setCreds({ ...creds, api_key: e.target.value })} autoComplete="off" />
          </div>
          <div>
            <Label>Bearer token</Label>
            <Input value={creds.token} onChange={(e) => setCreds({ ...creds, token: e.target.value })} autoComplete="off" />
          </div>
          <div className="sm:col-span-2">
            <Label>Cookie header</Label>
            <Input
              value={creds.cookie}
              onChange={(e) => setCreds({ ...creds, cookie: e.target.value })}
              placeholder="session=abc123"
              autoComplete="off"
            />
          </div>
        </div>
      </section>
    </>
  );
}
