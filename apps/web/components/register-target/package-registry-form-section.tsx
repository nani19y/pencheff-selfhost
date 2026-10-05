"use client";

import { Input, Label } from "@/components/brutal";

export type Ecosystem = "npm" | "pypi" | "maven" | "cargo" | "gem" | "composer" | "go" | "nuget";

export type PackageRegistryConfig = {
  kind: "package_registry";
  ecosystem: Ecosystem;
  package_list: Array<{ name: string; version: string }>;
  include_dev: boolean;
};

export const DEFAULT_PACKAGE_REGISTRY_CONFIG: PackageRegistryConfig = {
  kind: "package_registry",
  ecosystem: "npm",
  package_list: [],
  include_dev: false,
};

const ECOSYSTEMS: Array<{ id: Ecosystem; label: string; lockfile_hint: string }> = [
  { id: "npm", label: "npm / yarn / pnpm", lockfile_hint: "package-lock.json or yarn.lock" },
  { id: "pypi", label: "PyPI", lockfile_hint: "requirements.txt or Pipfile.lock" },
  { id: "maven", label: "Maven", lockfile_hint: "pom.xml (dependencies block)" },
  { id: "cargo", label: "Cargo (Rust)", lockfile_hint: "Cargo.lock" },
  { id: "gem", label: "RubyGems", lockfile_hint: "Gemfile.lock" },
  { id: "composer", label: "Composer (PHP)", lockfile_hint: "composer.lock" },
  { id: "go", label: "Go modules", lockfile_hint: "go.sum" },
  { id: "nuget", label: "NuGet (.NET)", lockfile_hint: "packages.lock.json" },
];

/**
 * Parse pasted dependency list. Accepts either a JSON object/array OR
 * one-per-line "name@version" format. Best-effort — operators can
 * paste straight from package.json's "dependencies" block.
 */
function parsePackageList(raw: string): PackageRegistryConfig["package_list"] {
  const trimmed = raw.trim();
  if (!trimmed) return [];
  // Try JSON object {"name":"version", …}
  try {
    const obj = JSON.parse(trimmed);
    if (obj && typeof obj === "object" && !Array.isArray(obj)) {
      return Object.entries(obj as Record<string, string>).map(([name, version]) => ({ name, version }));
    }
    if (Array.isArray(obj)) {
      return obj
        .filter((x) => x && typeof x === "object")
        .map((x) => ({ name: String((x as Record<string, unknown>).name ?? ""), version: String((x as Record<string, unknown>).version ?? "*") }));
    }
  } catch {
    // Fall through to text parse
  }
  // Text parse: name@version per line. Also tolerate "name version" / "name version".
  return trimmed
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const at = line.lastIndexOf("@");
      if (at > 0) return { name: line.slice(0, at), version: line.slice(at + 1) };
      const spaceMatch = line.match(/^([^\s]+)\s+(.+)$/);
      if (spaceMatch) return { name: spaceMatch[1], version: spaceMatch[2] };
      return { name: line, version: "*" };
    });
}

export function PackageRegistryFormSection({
  value,
  onChange,
  name,
  setName,
  rawPackages,
  setRawPackages,
}: {
  value: PackageRegistryConfig;
  onChange: (v: PackageRegistryConfig) => void;
  name: string;
  setName: (v: string) => void;
  rawPackages: string;
  setRawPackages: (v: string) => void;
}) {
  function onRawChange(raw: string) {
    setRawPackages(raw);
    const parsed = parsePackageList(raw);
    onChange({ ...value, package_list: parsed });
  }

  async function onFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 1024 * 1024) {
      alert("Package manifest must be ≤ 1 MiB.");
      return;
    }
    const text = await file.text();
    onRawChange(text);
  }

  const eco = ECOSYSTEMS.find((e) => e.id === value.ecosystem);

  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">PR1</span>
          <h2 className="font-display text-[18px] text-ink">Package Registry</h2>
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>Name (optional)</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="prod npm dependencies" />
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-4">
          <span className="eyebrow-gilt">PR2</span>
          <h2 className="font-display text-[18px] text-ink">Ecosystem</h2>
        </div>
        <div className="grid sm:grid-cols-2 gap-2" role="radiogroup" aria-label="Ecosystem">
          {ECOSYSTEMS.map((e) => {
            const active = value.ecosystem === e.id;
            return (
              <button
                key={e.id}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => onChange({ ...value, ecosystem: e.id })}
                className={
                  "text-left border rounded-sm p-3 transition-colors " +
                  (active ? "border-ink bg-vellum" : "border-hairline bg-paper hover:border-ink")
                }
              >
                <span className="block font-mono text-[12px] text-ink">{e.label}</span>
                <span className="mt-0.5 block font-mono text-[10px] text-mist">{e.lockfile_hint}</span>
              </button>
            );
          })}
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-4">
          <span className="eyebrow-gilt">PR3</span>
          <h2 className="font-display text-[18px] text-ink">Package list</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-4">
          Paste your <code>{eco?.lockfile_hint}</code> contents below, or upload the file. Accepts a JSON
          object (<code>{"{\"foo\": \"1.0.0\"}"}</code>), JSON array of objects, or plain <code>name@version</code> per line.
          Parsed: <strong>{value.package_list.length}</strong> packages.
        </p>
        <textarea
          required
          rows={12}
          value={rawPackages}
          onChange={(e) => onRawChange(e.target.value)}
          placeholder='{"lodash": "4.17.20", "axios": "0.21.0"}'
          className="w-full font-mono text-[12px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
        />
        <div className="mt-3 flex items-center gap-3">
          <input
            type="file"
            accept=".json,.txt,.lock"
            onChange={onFileUpload}
            className="font-mono text-[11px] text-slate"
          />
          <span className="font-mono text-[11px] text-mist">≤ 1 MiB</span>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={value.include_dev}
            onChange={(e) => onChange({ ...value, include_dev: e.target.checked })}
            className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
          />
          <span className="font-body text-[13px] text-ink">Include dev / test dependencies</span>
        </label>
      </section>
    </>
  );
}
