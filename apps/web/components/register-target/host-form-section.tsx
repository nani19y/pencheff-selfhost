"use client";

import { useMemo } from "react";

import { Badge, Button, Label } from "@/components/brutal";

export interface HostKindConfigDraft {
  kind: "host";
  hosts: string[];
}

interface Props {
  value: HostKindConfigDraft;
  onChange: (next: HostKindConfigDraft) => void;
  /** From `useOrg()` — server-side enforced; UI uses this only to render a warning. */
  allowPrivateTargets: boolean;
}

const MAX_HOSTS = 50;

const FQDN_RE = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$/;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;

function isPrivateIPv4(addr: string): boolean {
  if (!IPV4_RE.test(addr)) return false;
  const [a, b] = addr.split(".").map((n) => Number(n));
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

type LineStatus =
  | { kind: "ok"; warning?: "private" }
  | { kind: "error"; message: string };

function classifyLine(line: string): LineStatus {
  const trimmed = line.trim();
  if (!trimmed) return { kind: "error", message: "empty" };
  if (trimmed.includes("://")) return { kind: "error", message: "drop the URL scheme (e.g. 'https://')" };
  if (trimmed.includes(" ")) return { kind: "error", message: "no spaces allowed" };
  if (IPV4_RE.test(trimmed)) {
    return isPrivateIPv4(trimmed) ? { kind: "ok", warning: "private" } : { kind: "ok" };
  }
  if (IPV6_RE.test(trimmed) && trimmed.includes(":")) {
    const lower = trimmed.toLowerCase();
    if (lower === "::1" || lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd")) {
      return { kind: "ok", warning: "private" };
    }
    return { kind: "ok" };
  }
  if (FQDN_RE.test(trimmed)) return { kind: "ok" };
  return { kind: "error", message: "not a valid IP or FQDN" };
}

export function HostFormSection({ value, onChange, allowPrivateTargets }: Props) {
  const text = useMemo(() => value.hosts.join("\n"), [value.hosts]);

  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  const dedupedSet = new Set<string>();
  const linesWithStatus = lines.map((line) => {
    const status = classifyLine(line);
    const lower = line.toLowerCase();
    const isDuplicate = dedupedSet.has(lower);
    dedupedSet.add(lower);
    return { line, status, isDuplicate };
  });

  const hasErrors = linesWithStatus.some((l) => l.status.kind === "error");
  const privateCount = linesWithStatus.filter(
    (l) => l.status.kind === "ok" && l.status.warning === "private"
  ).length;
  const overLimit = lines.length > MAX_HOSTS;
  const hasDuplicates = linesWithStatus.some((l) => l.isDuplicate);

  function onTextChange(raw: string) {
    onChange({
      kind: "host",
      hosts: raw.split("\n").map((l) => l.trim()).filter(Boolean),
    });
  }

  function removeDuplicates() {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const l of lines) {
      const lower = l.toLowerCase();
      if (seen.has(lower)) continue;
      seen.add(lower);
      out.push(l);
    }
    onChange({ kind: "host", hosts: out });
  }

  return (
    <section className="space-y-3">
      <div>
        <Label htmlFor="host-list">Hosts</Label>
        <p className="font-mono text-[11px] text-mist mb-2">
          One host per line. FQDN (e.g. <code>box.example.com</code>) or IP
          (IPv4 / IPv6). Up to {MAX_HOSTS} hosts per target. Server resolves
          FQDNs at submit time — split-horizon DNS environments may resolve
          differently inside your network.
        </p>
      </div>
      <textarea
        id="host-list"
        rows={8}
        value={text}
        onChange={(e) => onTextChange(e.target.value)}
        placeholder={"box1.example.com\n203.0.113.10"}
        className="w-full font-mono text-[13px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
      />
      <div className="flex flex-wrap items-center gap-2">
        <Badge className={overLimit ? "border-oxblood text-oxblood" : undefined}>
          {lines.length} / {MAX_HOSTS} hosts
        </Badge>
        {hasErrors && (
          <Badge className="border-oxblood text-oxblood">
            {linesWithStatus.filter((l) => l.status.kind === "error").length} invalid
          </Badge>
        )}
        {privateCount > 0 && (
          <Badge className={allowPrivateTargets ? undefined : "border-oxblood text-oxblood"}>
            {privateCount} private —{" "}
            {allowPrivateTargets ? "allowed by org" : "requires org admin opt-in"}
          </Badge>
        )}
        {hasDuplicates && (
          <Button type="button" variant="yellow" onClick={removeDuplicates}>
            Remove duplicates
          </Button>
        )}
      </div>
      {hasErrors && (
        <ul className="space-y-1">
          {linesWithStatus
            .filter((l) => l.status.kind === "error")
            .map((l, i) => (
              <li key={`${l.line}-${i}`} className="font-mono text-[11px] text-oxblood">
                <code>{l.line}</code>: {(l.status as { kind: "error"; message: string }).message}
              </li>
            ))}
        </ul>
      )}
    </section>
  );
}
