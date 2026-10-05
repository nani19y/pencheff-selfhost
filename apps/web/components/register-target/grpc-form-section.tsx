"use client";

import { Input, Label } from "@/components/brutal";

export type GrpcConfig = {
  kind: "grpc";
  reflection_enabled: boolean;
  proto_files?: string[];
  tls_verify: boolean;
  plaintext: boolean;
};

export const DEFAULT_GRPC_CONFIG: GrpcConfig = {
  kind: "grpc",
  reflection_enabled: true,
  proto_files: undefined,
  tls_verify: true,
  plaintext: false,
};

export type GrpcMetadataRow = { key: string; value: string };

export const DEFAULT_GRPC_METADATA: GrpcMetadataRow[] = [
  { key: "authorization", value: "" },
];

export function GrpcFormSection({
  value,
  onChange,
  name,
  setName,
  authority,
  setAuthority,
  rawProto,
  setRawProto,
  metadata,
  setMetadata,
}: {
  value: GrpcConfig;
  onChange: (v: GrpcConfig) => void;
  name: string;
  setName: (v: string) => void;
  authority: string;
  setAuthority: (v: string) => void;
  /** Raw .proto textarea. Split into ``proto_files`` on submit. */
  rawProto: string;
  setRawProto: (v: string) => void;
  metadata: GrpcMetadataRow[];
  setMetadata: (rows: GrpcMetadataRow[]) => void;
}) {
  async function onProtoUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const files = e.target.files ? Array.from(e.target.files) : [];
    if (!files.length) return;
    const texts: string[] = [];
    for (const f of files) {
      if (f.size > 256 * 1024) {
        alert(`Each .proto file must be ≤ 256 KiB (${f.name} is larger).`);
        return;
      }
      texts.push(await f.text());
    }
    const combined = (rawProto ? rawProto + "\n\n" : "") + texts.join("\n\n");
    setRawProto(combined);
    onChange({ ...value, proto_files: texts });
  }

  function onRawProtoChange(raw: string) {
    setRawProto(raw);
    const blocks = raw
      .split(/^\s*\/\/\s*---\s*FILE BREAK\s*---/m)
      .map((s) => s.trim())
      .filter(Boolean);
    onChange({
      ...value,
      proto_files: blocks.length
        ? blocks
        : raw.trim()
          ? [raw.trim()]
          : undefined,
    });
  }

  function updateMetadata(idx: number, patch: Partial<GrpcMetadataRow>) {
    setMetadata(metadata.map((r, i) => (i === idx ? { ...r, ...patch } : r)));
  }

  function addMetadataRow() {
    setMetadata([...metadata, { key: "", value: "" }]);
  }

  function removeMetadataRow(idx: number) {
    setMetadata(metadata.filter((_, i) => i !== idx));
  }

  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">GR1</span>
          <h2 className="font-display text-[18px] text-ink">gRPC Service</h2>
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>Authority (gRPC endpoint)</Label>
            <Input
              required
              placeholder="grpc.example.com:443"
              value={authority}
              onChange={(e) => setAuthority(e.target.value)}
            />
            <p className="mt-1.5 font-mono text-[11px] text-mist">
              <code>host:port</code> form. Plain <code>grpc://</code> URLs
              accepted; TLS is on by default unless TLS verify is turned off.
            </p>
          </div>
          <div className="md:col-span-2">
            <Label>Name (optional)</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Trading gRPC API"
            />
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">GR2</span>
          <h2 className="font-display text-[18px] text-ink">
            Schema discovery
          </h2>
        </div>
        <p className="text-[13px] text-slate italic mb-4">
          With reflection on, the scanner discovers services via the gRPC
          reflection RPC. With reflection off, paste or upload the{" "}
          <code>.proto</code> definitions.
        </p>

        <label className="flex items-center gap-3 cursor-pointer mb-4">
          <input
            type="checkbox"
            checked={value.reflection_enabled}
            onChange={(e) =>
              onChange({
                ...value,
                reflection_enabled: e.target.checked,
                proto_files: e.target.checked ? undefined : value.proto_files,
              })
            }
            className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
          />
          <span className="font-body text-[13px] text-ink">
            Reflection is enabled on the server
          </span>
        </label>

        {!value.reflection_enabled && (
          <div>
            <Label>.proto contents (required when reflection is off)</Label>
            <textarea
              required
              rows={12}
              value={rawProto}
              onChange={(e) => onRawProtoChange(e.target.value)}
              placeholder={`syntax = "proto3";\n\nservice Trading {\n  rpc Place(Order) returns (Receipt);\n}`}
              className="w-full font-mono text-[11px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
            />
            <p className="mt-1.5 font-mono text-[11px] text-mist">
              Use <code>// --- FILE BREAK ---</code> on its own line to split
              multiple files.
            </p>
            <div className="mt-3 flex items-center gap-3">
              <input
                type="file"
                accept=".proto"
                multiple
                onChange={onProtoUpload}
                className="font-mono text-[11px] text-slate"
              />
              <span className="font-mono text-[11px] text-mist">
                ≤ 256 KiB each
              </span>
            </div>
          </div>
        )}

        <label className="mt-5 flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={value.plaintext}
            onChange={(e) =>
              onChange({ ...value, plaintext: e.target.checked })
            }
            className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
          />
          <span className="font-body text-[13px] text-ink">
            Plaintext h2c — no TLS (common for internal gRPC; required to probe
            a non-TLS endpoint)
          </span>
        </label>

        <label
          className={`mt-3 flex items-center gap-3 ${value.plaintext ? "opacity-40 cursor-not-allowed" : "cursor-pointer"}`}
        >
          <input
            type="checkbox"
            checked={value.tls_verify}
            disabled={value.plaintext}
            onChange={(e) =>
              onChange({ ...value, tls_verify: e.target.checked })
            }
            className="w-[16px] h-[16px] border border-hairline rounded-sm accent-ink"
          />
          <span className="font-body text-[13px] text-ink">
            Verify the server TLS certificate (turn off for self-signed staging
            only){value.plaintext ? " — N/A while plaintext is on" : ""}
          </span>
        </label>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">GR3</span>
          <h2 className="font-display text-[18px] text-ink">Auth metadata</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-4">
          gRPC carries auth via per-call metadata (HTTP/2 headers). Common keys:
          <code> authorization</code>, <code>x-api-key</code>. Stored encrypted
          with Fernet.
        </p>
        <div className="space-y-2">
          {metadata.map((row, idx) => (
            <div key={idx} className="grid sm:grid-cols-[1fr_2fr_auto] gap-2">
              <Input
                placeholder="header name"
                value={row.key}
                onChange={(e) => updateMetadata(idx, { key: e.target.value })}
                autoComplete="off"
              />
              <Input
                placeholder="value"
                value={row.value}
                onChange={(e) => updateMetadata(idx, { value: e.target.value })}
                autoComplete="off"
              />
              <button
                type="button"
                onClick={() => removeMetadataRow(idx)}
                className="font-mono text-[11px] text-mist hover:text-rust px-2"
                aria-label="Remove header"
              >
                ✕
              </button>
            </div>
          ))}
        </div>
        <button
          type="button"
          onClick={addMetadataRow}
          className="mt-3 font-mono text-[11px] text-slate hover:text-ink underline underline-offset-[3px] decoration-hairline"
        >
          + Add header
        </button>
      </section>
    </>
  );
}
