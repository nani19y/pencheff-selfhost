"use client";

import { Input, Label } from "@/components/brutal";

export type WebAppConfig = {
  kind: "web_app";
  crawl_depth: number;
  max_pages: number;
  browser_render: boolean;
  api_spec_url?: string;
};

export const DEFAULT_WEB_APP_CONFIG: WebAppConfig = {
  kind: "web_app",
  crawl_depth: 3,
  max_pages: 100,
  browser_render: true,
  api_spec_url: "",
};

export type WebAppCredentials = {
  username: string;
  password: string;
  api_key: string;
  token: string;
  cookie: string;
};

export const EMPTY_WEB_APP_CREDS: WebAppCredentials = {
  username: "", password: "", api_key: "", token: "", cookie: "",
};

export function WebAppFormSection({
  value,
  onChange,
  name,
  setName,
  appUrl,
  setAppUrl,
  creds,
  setCreds,
}: {
  value: WebAppConfig;
  onChange: (v: WebAppConfig) => void;
  name: string;
  setName: (v: string) => void;
  appUrl: string;
  setAppUrl: (v: string) => void;
  creds: WebAppCredentials;
  setCreds: (v: WebAppCredentials) => void;
}) {
  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">W1</span>
          <h2 className="font-display text-[18px] text-ink">Web Application</h2>
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>Application URL</Label>
            <Input
              required
              type="url"
              placeholder="https://staging.example.com"
              value={appUrl}
              onChange={(e) => setAppUrl(e.target.value)}
            />
          </div>
          <div className="md:col-span-2">
            <Label>Name (optional)</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Staging Web App" />
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">W2</span>
          <h2 className="font-display text-[18px] text-ink">Crawl coverage</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-4">
          Controls how deep the headless crawler walks the app before DAST kicks in.
        </p>
        <div className="grid sm:grid-cols-2 gap-5">
          <div>
            <Label>Crawl depth (1–10)</Label>
            <Input
              type="number"
              min={1}
              max={10}
              value={value.crawl_depth}
              onChange={(e) => onChange({ ...value, crawl_depth: Math.max(1, Math.min(10, Number(e.target.value) || 1)) })}
            />
          </div>
          <div>
            <Label>Max pages (1–1000)</Label>
            <Input
              type="number"
              min={1}
              max={1000}
              value={value.max_pages}
              onChange={(e) => onChange({ ...value, max_pages: Math.max(1, Math.min(1000, Number(e.target.value) || 1)) })}
            />
          </div>
          <label className="flex items-center gap-3 cursor-pointer sm:col-span-2">
            <input
              type="checkbox"
              checked={value.browser_render}
              onChange={(e) => onChange({ ...value, browser_render: e.target.checked })}
              className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
            />
            <span className="font-body text-[13px] text-ink">
              Render JavaScript via headless Chromium (slower, finds SPA routes)
            </span>
          </label>
          <div className="sm:col-span-2">
            <Label>OpenAPI / Swagger spec URL (optional)</Label>
            <Input
              type="url"
              placeholder="https://staging.example.com/openapi.json"
              value={value.api_spec_url ?? ""}
              onChange={(e) => onChange({ ...value, api_spec_url: e.target.value })}
            />
            <p className="mt-1.5 font-mono text-[11px] text-mist">
              If the web app exposes an API spec, the scanner uses it to seed endpoint discovery.
            </p>
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">W3</span>
          <h2 className="font-display text-[18px] text-ink">Credentials</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-6">
          Optional — enables authenticated coverage. Stored encrypted with Fernet.
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
              placeholder="session=abc123; XSRF-TOKEN=…"
              autoComplete="off"
            />
          </div>
        </div>
      </section>
    </>
  );
}
