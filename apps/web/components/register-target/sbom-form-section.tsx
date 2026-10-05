"use client";

import { useState } from "react";
import { Input, Label } from "@/components/brutal";

export type SbomFormat = "cyclonedx-json" | "cyclonedx-xml" | "spdx-json" | "spdx-tag-value";

export type SbomConfig = {
  kind: "sbom";
  format: SbomFormat;
  content?: string;
  url?: string;
  check_licenses: boolean;
  check_suppliers: boolean;
};

export const DEFAULT_SBOM_CONFIG: SbomConfig = {
  kind: "sbom",
  format: "cyclonedx-json",
  check_licenses: true,
  check_suppliers: true,
};

const FORMATS: Array<{ id: SbomFormat; label: string }> = [
  { id: "cyclonedx-json", label: "CycloneDX (JSON)" },
  { id: "cyclonedx-xml",  label: "CycloneDX (XML)" },
  { id: "spdx-json",      label: "SPDX (JSON)" },
  { id: "spdx-tag-value", label: "SPDX (tag-value)" },
];

// Backend caps at 16 MiB; reject early on the client.
const MAX_BYTES = 16 * 1024 * 1024;

export function SbomFormSection({
  value,
  onChange,
  name,
  setName,
}: {
  value: SbomConfig;
  onChange: (v: SbomConfig) => void;
  name: string;
  setName: (v: string) => void;
}) {
  const [mode, setMode] = useState<"paste" | "url">(value.content !== undefined ? "paste" : "url");
  const [fileName, setFileName] = useState<string>("");

  async function onFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > MAX_BYTES) {
      alert("SBOM must be ≤ 16 MiB.");
      return;
    }
    const text = await file.text();
    setFileName(file.name);
    onChange({ ...value, content: text, url: undefined });
  }

  function switchMode(m: "paste" | "url") {
    setMode(m);
    if (m === "paste") onChange({ ...value, url: undefined });
    else onChange({ ...value, content: undefined });
  }

  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">SB1</span>
          <h2 className="font-display text-[18px] text-ink">Software Bill of Materials</h2>
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>Name (optional)</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="prod-api SBOM 2026-Q1" />
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-4">
          <span className="eyebrow-gilt">SB2</span>
          <h2 className="font-display text-[18px] text-ink">Format</h2>
        </div>
        <div className="grid sm:grid-cols-2 gap-2" role="radiogroup" aria-label="SBOM format">
          {FORMATS.map((f) => {
            const active = value.format === f.id;
            return (
              <button
                key={f.id}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => onChange({ ...value, format: f.id })}
                className={
                  "text-left border rounded-sm p-3 transition-colors " +
                  (active ? "border-ink bg-vellum" : "border-hairline bg-paper hover:border-ink")
                }
              >
                <span className="block font-mono text-[12px] text-ink">{f.label}</span>
              </button>
            );
          })}
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-4">
          <span className="eyebrow-gilt">SB3</span>
          <h2 className="font-display text-[18px] text-ink">Source</h2>
        </div>
        <div className="grid sm:grid-cols-2 gap-3 mb-5" role="radiogroup" aria-label="SBOM source">
          {(["paste", "url"] as const).map((m) => {
            const active = mode === m;
            return (
              <button
                key={m}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => switchMode(m)}
                className={
                  "text-left border rounded-sm p-4 transition-colors " +
                  (active ? "border-ink bg-vellum" : "border-hairline bg-paper hover:border-ink")
                }
              >
                <span className="block font-mono text-[12px] text-ink">
                  {m === "paste" ? "Paste / Upload" : "Remote URL"}
                </span>
                <span className="mt-1 block font-mono text-[11px] text-mist">
                  {m === "paste"
                    ? "Inline SBOM content (≤ 16 MiB)"
                    : "HTTPS URL to a hosted SBOM"}
                </span>
              </button>
            );
          })}
        </div>

        {mode === "paste" ? (
          <>
            <textarea
              required
              rows={14}
              value={value.content ?? ""}
              onChange={(e) => onChange({ ...value, content: e.target.value })}
              placeholder='{"bomFormat":"CycloneDX","specVersion":"1.4","components":[…]}'
              className="w-full font-mono text-[11px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
            />
            <div className="mt-3 flex items-center gap-3">
              <input
                type="file"
                accept=".json,.xml,.spdx,.txt"
                onChange={onFileUpload}
                className="font-mono text-[11px] text-slate"
              />
              <span className="font-mono text-[11px] text-mist">
                {fileName ? `Loaded: ${fileName}` : "≤ 16 MiB"}
              </span>
            </div>
          </>
        ) : (
          <div>
            <Label>SBOM URL</Label>
            <Input
              required
              type="url"
              placeholder="https://artifacts.example.com/sboms/prod-api-2026-q1.json"
              value={value.url ?? ""}
              onChange={(e) => onChange({ ...value, url: e.target.value })}
            />
            <p className="mt-1.5 font-mono text-[11px] text-mist">
              Host must be on the operator-registered allowlist; default allow includes
              registry.npmjs.org / pypi.org / etc.
            </p>
          </div>
        )}
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-3">
          <span className="eyebrow-gilt">SB4</span>
          <h2 className="font-display text-[18px] text-ink">Coverage</h2>
        </div>
        <div className="space-y-3">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={value.check_licenses}
              onChange={(e) => onChange({ ...value, check_licenses: e.target.checked })}
              className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
            />
            <span className="font-body text-[13px] text-ink">License compliance (GPL/AGPL in commercial code, etc.)</span>
          </label>
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={value.check_suppliers}
              onChange={(e) => onChange({ ...value, check_suppliers: e.target.checked })}
              className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
            />
            <span className="font-body text-[13px] text-ink">Supplier risk (unmaintained / sanctioned / typosquat)</span>
          </label>
        </div>
      </section>
    </>
  );
}
