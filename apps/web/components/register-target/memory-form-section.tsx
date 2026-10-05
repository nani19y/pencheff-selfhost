"use client";

import { Input, Label } from "@/components/brutal";
import { FieldHint, HeaderRowsEditor, SectionIntro } from "./form-helpers";

export type MemorySourceType =
  | "manual_items"
  | "file_upload"
  | "mem0"
  | "zep"
  | "langgraph_store"
  | "redis"
  | "pinecone"
  | "chroma"
  | "qdrant"
  | "weaviate"
  | "custom_http";

export type MemoryFileFormat = "auto" | "txt" | "json" | "jsonl" | "csv" | "md";
export type MemoryHeaderRow = { key: string; value: string };

const SOURCE_TYPE_OPTIONS: {
  value: MemorySourceType;
  label: string;
  body: string;
}[] = [
  {
    value: "manual_items",
    label: "Paste items",
    body: "Paste memory rows, retrieved docs, or RAG chunks directly.",
  },
  {
    value: "file_upload",
    label: "Local file",
    body: "Upload .txt, .md, .json, .jsonl, or .csv and review parsed rows before saving.",
  },
  {
    value: "mem0",
    label: "Mem0",
    body: "Register Mem0 endpoint, auth, and user or namespace scope.",
  },
  {
    value: "zep",
    label: "Zep",
    body: "Register Zep endpoint, auth, and session or user scope.",
  },
  {
    value: "langgraph_store",
    label: "LangGraph Store",
    body: "Register LangGraph Store endpoint, auth, namespace, or thread scope.",
  },
  {
    value: "redis",
    label: "Redis",
    body: "Register Redis or Redis Stack memory export details.",
  },
  {
    value: "pinecone",
    label: "Pinecone",
    body: "Register Pinecone endpoint, API key header, index, and namespace.",
  },
  {
    value: "chroma",
    label: "Chroma",
    body: "Register Chroma endpoint, auth, and collection scope.",
  },
  {
    value: "qdrant",
    label: "Qdrant",
    body: "Register Qdrant endpoint, auth, and collection scope.",
  },
  {
    value: "weaviate",
    label: "Weaviate",
    body: "Register Weaviate REST endpoint, auth, and collection scope.",
  },
  {
    value: "custom_http",
    label: "Custom HTTP",
    body: "Register an internal memory export endpoint with request and response templates.",
  },
];

const PROVIDER_SOURCES: MemorySourceType[] = [
  "mem0",
  "zep",
  "langgraph_store",
  "redis",
  "pinecone",
  "chroma",
  "qdrant",
  "weaviate",
  "custom_http",
];

function inferFormat(fileName: string): MemoryFileFormat {
  const lower = fileName.toLowerCase();
  if (lower.endsWith(".jsonl")) return "jsonl";
  if (lower.endsWith(".json")) return "json";
  if (lower.endsWith(".csv")) return "csv";
  if (lower.endsWith(".md") || lower.endsWith(".markdown")) return "md";
  if (lower.endsWith(".txt")) return "txt";
  return "auto";
}

function textFromRecord(value: unknown): string {
  if (typeof value === "string") return value.trim();
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return String(value ?? "").trim();
  }

  const record = value as Record<string, unknown>;
  const candidate =
    record.text ??
    record.content ??
    record.memory ??
    record.value ??
    record.document ??
    record.chunk ??
    record.transcript;
  const text =
    typeof candidate === "string"
      ? candidate.trim()
      : candidate
        ? JSON.stringify(candidate)
        : JSON.stringify(record);

  if (!text) return "";

  const structured: Record<string, unknown> = { text };
  for (const key of ["id", "namespace", "source"]) {
    if (typeof record[key] === "string" && record[key]) {
      structured[key] = record[key];
    }
  }
  return Object.keys(structured).length > 1 ? JSON.stringify(structured) : text;
}

function parseJsonMemory(text: string): string[] {
  const parsed = JSON.parse(text);
  const rows = Array.isArray(parsed)
    ? parsed
    : Array.isArray(parsed?.items)
      ? parsed.items
      : Array.isArray(parsed?.memories)
        ? parsed.memories
        : Array.isArray(parsed?.documents)
          ? parsed.documents
          : [parsed];
  return rows.map(textFromRecord).filter(Boolean);
}

function parseJsonlMemory(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      try {
        return textFromRecord(JSON.parse(line));
      } catch {
        return line;
      }
    })
    .filter(Boolean);
}

function parseCsvLine(line: string): string[] {
  const cells: string[] = [];
  let current = "";
  let quoted = false;
  for (let idx = 0; idx < line.length; idx += 1) {
    const char = line[idx];
    const next = line[idx + 1];
    if (char === '"' && quoted && next === '"') {
      current += '"';
      idx += 1;
    } else if (char === '"') {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      cells.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }
  cells.push(current.trim());
  return cells;
}

function parseCsvMemory(text: string): string[] {
  const rows = text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map(parseCsvLine);
  if (!rows.length) return [];
  const header = rows[0].map((cell) => cell.toLowerCase());
  const textIndex = ["text", "content", "memory", "document", "chunk"].reduce(
    (found, key) => (found >= 0 ? found : header.indexOf(key)),
    -1,
  );
  const dataRows = textIndex >= 0 ? rows.slice(1) : rows;
  return dataRows
    .map((row) => (textIndex >= 0 ? row[textIndex] : row.join(" ")).trim())
    .filter(Boolean);
}

function parsePlainMemory(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function parseMemoryFile(text: string, format: MemoryFileFormat): string[] {
  try {
    if (format === "json") return parseJsonMemory(text);
    if (format === "jsonl") return parseJsonlMemory(text);
    if (format === "csv") return parseCsvMemory(text);
    if (format === "auto") {
      const trimmed = text.trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        return parseJsonMemory(text);
      }
      if (trimmed.includes("\n{")) return parseJsonlMemory(text);
    }
  } catch {
    return parsePlainMemory(text);
  }
  return parsePlainMemory(text);
}

/** Register form section for the `memory` target kind: a name + a batch of
 *  memory items (one per line). Items are scanned on the target page via the
 *  memory scanner (secrets at rest + poisoning); they may be left empty here
 *  and added later. Mirrors the shared-`artifactName` pattern of the other
 *  kind_config-only sections. */
export function MemoryFormSection({
  name,
  setName,
  sourceType,
  setSourceType,
  url,
  setUrl,
  orgId,
  setOrgId,
  projectId,
  setProjectId,
  userId,
  setUserId,
  sessionId,
  setSessionId,
  collection,
  setCollection,
  namespace,
  setNamespace,
  indexName,
  setIndexName,
  fileName,
  setFileName,
  fileFormat,
  setFileFormat,
  requestTemplate,
  setRequestTemplate,
  responsePath,
  setResponsePath,
  headerRows,
  setHeaderRows,
  rawItems,
  setRawItems,
}: {
  name: string;
  setName: (v: string) => void;
  sourceType: MemorySourceType;
  setSourceType: (v: MemorySourceType) => void;
  url: string;
  setUrl: (v: string) => void;
  orgId: string;
  setOrgId: (v: string) => void;
  projectId: string;
  setProjectId: (v: string) => void;
  userId: string;
  setUserId: (v: string) => void;
  sessionId: string;
  setSessionId: (v: string) => void;
  collection: string;
  setCollection: (v: string) => void;
  namespace: string;
  setNamespace: (v: string) => void;
  indexName: string;
  setIndexName: (v: string) => void;
  fileName: string;
  setFileName: (v: string) => void;
  fileFormat: MemoryFileFormat;
  setFileFormat: (v: MemoryFileFormat) => void;
  requestTemplate: string;
  setRequestTemplate: (v: string) => void;
  responsePath: string;
  setResponsePath: (v: string) => void;
  headerRows: MemoryHeaderRow[];
  setHeaderRows: (v: MemoryHeaderRow[]) => void;
  rawItems: string;
  setRawItems: (v: string) => void;
}) {
  const isProviderSource = PROVIDER_SOURCES.includes(sourceType);
  const sourceBody = SOURCE_TYPE_OPTIONS.find(
    (option) => option.value === sourceType,
  )?.body;
  const count = rawItems
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean).length;

  async function handleFile(file: File | null) {
    if (!file) return;
    const format = inferFormat(file.name);
    const text = await file.text();
    const items = parseMemoryFile(text, format);
    setFileName(file.name);
    setFileFormat(format);
    setRawItems(items.join("\n"));
  }

  return (
    <section className="space-y-8">
      <SectionIntro
        eyebrow="Agent Memory / Vector Store"
        title="Register the memory source"
        description="Choose where the agent memory lives. Pencheff checks stored memories, RAG chunks, and retrieved documents for secrets, PII, and memory-poisoning risk."
      />

      <div className="grid gap-5 md:grid-cols-2">
        <div>
          <Label htmlFor="memory_name">Name</Label>
          <Input
            id="memory_name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Support-bot long-term memory"
          />
          <FieldHint>A friendly name for this memory source.</FieldHint>
        </div>
        <div>
          <Label>Memory source</Label>
          <select
            value={sourceType}
            onChange={(e) => setSourceType(e.target.value as MemorySourceType)}
            className="block w-full border border-hairline bg-paper p-3 font-mono text-[13px] text-graphite focus:outline-none focus:border-ink"
          >
            {SOURCE_TYPE_OPTIONS.map(({ value, label }) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          <FieldHint>{sourceBody}</FieldHint>
        </div>
      </div>

      {isProviderSource && (
        <div className="space-y-5">
          <div>
            <Label>Provider endpoint</Label>
            <Input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={
                sourceType === "mem0"
                  ? "https://api.mem0.ai"
                  : sourceType === "zep"
                    ? "https://your-zep-host"
                    : sourceType === "custom_http"
                      ? "https://your-api.example.com/memories/export"
                      : "https://your-memory-provider"
              }
              className="font-mono text-[13px]"
            />
            <FieldHint>
              Use the API base URL or export endpoint for this provider.
            </FieldHint>
          </div>

          <div className="grid gap-5 md:grid-cols-3">
            <div>
              <Label>Org ID</Label>
              <Input
                value={orgId}
                onChange={(e) => setOrgId(e.target.value)}
                placeholder="org_..."
                className="font-mono text-[13px]"
              />
            </div>
            <div>
              <Label>Project ID</Label>
              <Input
                value={projectId}
                onChange={(e) => setProjectId(e.target.value)}
                placeholder="proj_..."
                className="font-mono text-[13px]"
              />
            </div>
            <div>
              <Label>User ID</Label>
              <Input
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                placeholder="user_123"
                className="font-mono text-[13px]"
              />
            </div>
            <div>
              <Label>Session ID</Label>
              <Input
                value={sessionId}
                onChange={(e) => setSessionId(e.target.value)}
                placeholder="session_123"
                className="font-mono text-[13px]"
              />
            </div>
            <div>
              <Label>Collection</Label>
              <Input
                value={collection}
                onChange={(e) => setCollection(e.target.value)}
                placeholder="support_memory"
                className="font-mono text-[13px]"
              />
            </div>
            <div>
              <Label>Namespace</Label>
              <Input
                value={namespace}
                onChange={(e) => setNamespace(e.target.value)}
                placeholder="prod"
                className="font-mono text-[13px]"
              />
            </div>
            <div>
              <Label>Index name</Label>
              <Input
                value={indexName}
                onChange={(e) => setIndexName(e.target.value)}
                placeholder="memory-index"
                className="font-mono text-[13px]"
              />
            </div>
          </div>

          {sourceType === "custom_http" && (
            <div className="grid gap-5 md:grid-cols-2">
              <div>
                <Label>Request template</Label>
                <textarea
                  value={requestTemplate}
                  onChange={(e) => setRequestTemplate(e.target.value)}
                  rows={4}
                  placeholder='{"user_id":"{{user_id}}","namespace":"{{namespace}}","limit":500}'
                  className="block w-full border border-hairline bg-paper p-3 font-mono text-[12px] text-graphite focus:outline-none focus:border-ink"
                />
              </div>
              <div>
                <Label>Response path</Label>
                <Input
                  value={responsePath}
                  onChange={(e) => setResponsePath(e.target.value)}
                  placeholder="$.memories[*].text"
                  className="font-mono text-[13px]"
                />
                <FieldHint>
                  JSONPath that returns memory text rows or objects with a text
                  field.
                </FieldHint>
              </div>
            </div>
          )}

          <div>
            <SectionIntro
              title="Authentication"
              description="Add bearer tokens, API keys, or tenant headers needed to read memory rows. They are stored encrypted with the target."
            />
            <HeaderRowsEditor
              rows={headerRows}
              setRows={setHeaderRows}
              emptyLabel="No headers yet. Add one if this memory provider requires a token."
            />
          </div>
        </div>
      )}

      {sourceType === "file_upload" && (
        <div className="grid gap-5 md:grid-cols-2">
          <div>
            <Label htmlFor="memory_file">Upload memory file</Label>
            <Input
              id="memory_file"
              type="file"
              accept=".txt,.md,.markdown,.json,.jsonl,.csv,application/json,text/plain,text/csv"
              onChange={(e) => {
                void handleFile(e.target.files?.[0] ?? null);
              }}
              className="font-mono text-[13px]"
            />
            <FieldHint>
              The file is parsed in your browser. Review the rows below before
              saving.
            </FieldHint>
          </div>
          <div>
            <Label>Detected file</Label>
            <Input
              value={fileName}
              onChange={(e) => setFileName(e.target.value)}
              placeholder="memory.jsonl"
              className="font-mono text-[13px]"
            />
            <FieldHint>Format: {fileFormat}</FieldHint>
          </div>
        </div>
      )}

      <div>
        <Label htmlFor="memory_items">Memory items (one per line)</Label>
        <textarea
          id="memory_items"
          value={rawItems}
          onChange={(e) => setRawItems(e.target.value)}
          rows={8}
          placeholder={"User prefers dark mode...\nRetrieved doc: refund policy for enterprise plan...\nMemory: customer asked about SSO setup..."}
          className="block w-full border border-hairline bg-paper p-3 font-mono text-[12px] text-graphite focus:outline-none focus:border-ink"
        />
        <p className="mt-2 text-[12px] text-slate">
          {count} item{count === 1 ? "" : "s"}.
        </p>
      </div>
    </section>
  );
}
