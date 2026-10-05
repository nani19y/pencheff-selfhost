"use client";

import { Input, Label } from "@/components/brutal";
import {
  AdvancedSection,
  FieldHint,
  HeaderRowsEditor,
  SectionIntro,
} from "./form-helpers";

type RagSourceType =
  | "managed_vdb"
  | "self_hosted_vdb"
  | "rag_endpoint"
  | "embedding_artifact";

type VdbProvider =
  | "pinecone"
  | "weaviate"
  | "qdrant"
  | "chroma"
  | "milvus"
  | "pgvector"
  | "redis";

type LlmProvider =
  | "openai-chat"
  | "custom"
  | "executable"
  | "websocket"
  | "bedrock"
  | "vertex"
  | "azure-openai";

type HeaderRow = { key: string; value: string };

const SOURCE_TYPE_OPTIONS: {
  value: RagSourceType;
  label: string;
  help: string;
}[] = [
  {
    value: "managed_vdb",
    label: "Managed vector DB",
    help: "Pinecone, Weaviate Cloud, Qdrant Cloud, or a similar hosted index.",
  },
  {
    value: "self_hosted_vdb",
    label: "Self-hosted vector DB",
    help: "A vector database your team runs, such as pgvector, Chroma, Milvus, Redis, or Qdrant.",
  },
  {
    value: "rag_endpoint",
    label: "RAG endpoint",
    help: "A live API that accepts a question, retrieves context, and returns an answer.",
  },
  {
    value: "embedding_artifact",
    label: "Exported chunks",
    help: "A pasted export of retrieved chunks, documents, or embedding records.",
  },
];

const VDB_PROVIDER_OPTIONS: { value: VdbProvider; label: string }[] = [
  { value: "pinecone", label: "Pinecone" },
  { value: "weaviate", label: "Weaviate" },
  { value: "qdrant", label: "Qdrant" },
  { value: "chroma", label: "Chroma" },
  { value: "milvus", label: "Milvus" },
  { value: "pgvector", label: "Postgres pgvector" },
  { value: "redis", label: "Redis Stack" },
];

const LLM_PROVIDER_OPTIONS: { value: LlmProvider; label: string }[] = [
  { value: "openai-chat", label: "OpenAI-compatible" },
  { value: "bedrock", label: "AWS Bedrock" },
  { value: "vertex", label: "Google Vertex AI" },
  { value: "azure-openai", label: "Azure OpenAI" },
  { value: "custom", label: "Custom template" },
  { value: "websocket", label: "WebSocket" },
  { value: "executable", label: "Executable" },
];

export function RagFormSection({
  name,
  setName,
  sourceType,
  setSourceType,
  provider,
  setProvider,
  url,
  setUrl,
  indexName,
  setIndexName,
  namespace,
  setNamespace,
  providerLlm,
  setProviderLlm,
  requestTemplate,
  setRequestTemplate,
  responsePath,
  setResponsePath,
  items,
  setItems,
  canaryText,
  setCanaryText,
  queryProbes,
  setQueryProbes,
  poisonInjectionOptIn,
  setPoisonInjectionOptIn,
  headerRows,
  setHeaderRows,
}: {
  name: string;
  setName: (v: string) => void;
  sourceType: RagSourceType;
  setSourceType: (v: RagSourceType) => void;
  provider: string;
  setProvider: (v: string) => void;
  url: string;
  setUrl: (v: string) => void;
  indexName: string;
  setIndexName: (v: string) => void;
  namespace: string;
  setNamespace: (v: string) => void;
  providerLlm: string;
  setProviderLlm: (v: string) => void;
  requestTemplate: string;
  setRequestTemplate: (v: string) => void;
  responsePath: string;
  setResponsePath: (v: string) => void;
  items: string;
  setItems: (v: string) => void;
  canaryText: string;
  setCanaryText: (v: string) => void;
  queryProbes: boolean;
  setQueryProbes: (v: boolean) => void;
  poisonInjectionOptIn: boolean;
  setPoisonInjectionOptIn: (v: boolean) => void;
  headerRows: HeaderRow[];
  setHeaderRows: (v: HeaderRow[]) => void;
}) {
  const selectedSource = SOURCE_TYPE_OPTIONS.find(
    (option) => option.value === sourceType,
  );
  const isVectorDb =
    sourceType === "managed_vdb" || sourceType === "self_hosted_vdb";

  return (
    <div className="space-y-8">
      <section>
        <SectionIntro
          eyebrow="RAG / Vector DB"
          title="Point Pencheff at the knowledge source"
          description="Register either the vector database itself, the live RAG API, or a pasted export of chunks. Start with the option that matches what you can access today."
        />
        <div className="grid gap-5 md:grid-cols-2">
          <div>
            <Label>Name</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Production knowledge base"
            />
          </div>
          <div>
            <Label>Source type</Label>
            <select
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value as RagSourceType)}
              className="block w-full border border-hairline bg-paper px-3 py-2 text-[13px] text-graphite focus:outline-none focus:border-ink"
            >
              {SOURCE_TYPE_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            {selectedSource && <FieldHint>{selectedSource.help}</FieldHint>}
          </div>

          {isVectorDb && (
            <>
              <div>
                <Label>Vector DB provider</Label>
                <select
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                  className="block w-full border border-hairline bg-paper px-3 py-2 text-[13px] text-graphite focus:outline-none focus:border-ink"
                >
                  {VDB_PROVIDER_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <Label>Index / collection / table</Label>
                <Input
                  value={indexName}
                  onChange={(e) => setIndexName(e.target.value)}
                  placeholder="support-docs-prod"
                  className="font-mono text-[13px]"
                />
              </div>
              <div className="md:col-span-2">
                <Label>Endpoint / connection URL</Label>
                <Input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://your-index.svc.pinecone.io"
                  className="font-mono text-[13px]"
                />
              </div>
            </>
          )}

          {sourceType === "rag_endpoint" && (
            <>
              <div>
                <Label>RAG endpoint provider</Label>
                <select
                  value={providerLlm}
                  onChange={(e) => setProviderLlm(e.target.value)}
                  className="block w-full border border-hairline bg-paper px-3 py-2 text-[13px] text-graphite focus:outline-none focus:border-ink"
                >
                  {LLM_PROVIDER_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <Label>RAG endpoint URL</Label>
                <Input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://api.example.com/rag/query"
                  className="font-mono text-[13px]"
                />
              </div>
              {providerLlm === "custom" && (
                <div className="grid gap-5 md:col-span-2 md:grid-cols-2">
                  <div>
                    <Label>Request body template (JSON)</Label>
                    <textarea
                      value={requestTemplate}
                      onChange={(e) => setRequestTemplate(e.target.value)}
                      rows={4}
                      className="block w-full border border-hairline bg-paper p-3 font-mono text-[12px] text-graphite focus:outline-none focus:border-ink"
                    />
                  </div>
                  <div>
                    <Label>Response JSONPath</Label>
                    <Input
                      value={responsePath}
                      onChange={(e) => setResponsePath(e.target.value)}
                      placeholder="$.choices[0].message.content"
                      className="font-mono text-[13px]"
                    />
                  </div>
                </div>
              )}
            </>
          )}

          {sourceType === "embedding_artifact" && (
            <div className="md:col-span-2">
              <Label>Chunks / records</Label>
              <textarea
                value={items}
                onChange={(e) => setItems(e.target.value)}
                rows={8}
                placeholder={"Retrieved doc: password reset policy...\nChunk: pricing policy for enterprise customers..."}
                className="block w-full border border-hairline bg-paper p-3 font-mono text-[12px] text-graphite focus:outline-none focus:border-ink"
              />
              <FieldHint>Paste one chunk, document, or record per line.</FieldHint>
            </div>
          )}
        </div>
      </section>

      {sourceType !== "embedding_artifact" && (
        <section>
          <SectionIntro
            title="Authentication"
            description="Add a bearer token or API key if the database or endpoint requires one."
          />
          <HeaderRowsEditor rows={headerRows} setRows={setHeaderRows} />
        </section>
      )}

      <AdvancedSection
        title="Advanced RAG scan settings"
        description="Use these for tenant scoping, canary text, read-only query probes, or controlled poisoning tests."
      >
        {isVectorDb && (
          <div>
            <Label>Namespace / tenant</Label>
            <Input
              value={namespace}
              onChange={(e) => setNamespace(e.target.value)}
              placeholder="default"
              className="font-mono text-[13px]"
            />
          </div>
        )}

        <div>
          <h3 className="mb-4 font-display text-[16px] text-ink">
            Dynamic testing
          </h3>
          <div className="grid gap-5">
            <label className="inline-flex items-center gap-2 text-[13px] text-graphite">
              <input
                type="checkbox"
                checked={queryProbes}
                onChange={(e) => {
                  const next = e.target.checked;
                  setQueryProbes(next);
                  if (!next) setPoisonInjectionOptIn(false);
                }}
              />
              Run read-only query probes
            </label>

            {queryProbes && (
              <>
                <div>
                  <Label>Canary text</Label>
                  <Input
                    value={canaryText}
                    onChange={(e) => setCanaryText(e.target.value)}
                    placeholder="pencheff-canary-2026"
                    className="font-mono text-[13px]"
                  />
                  <FieldHint>
                    Optional phrase used to check whether private context leaks
                    back through search.
                  </FieldHint>
                </div>
                <div>
                  <label className="inline-flex items-center gap-2 text-[13px] text-graphite">
                    <input
                      type="checkbox"
                      checked={poisonInjectionOptIn}
                      disabled={!queryProbes}
                      onChange={(e) =>
                        setPoisonInjectionOptIn(e.target.checked)
                      }
                    />
                    Allow poisoning injection
                  </label>
                  <FieldHint>
                    This writes test documents to the index. Use only on a
                    sandbox or index you are allowed to modify.
                  </FieldHint>
                </div>
              </>
            )}
          </div>
        </div>
      </AdvancedSection>
    </div>
  );
}
