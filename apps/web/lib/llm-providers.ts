import { api } from "./api";

export type LlmProviderKind =
  | "openai"
  | "anthropic"
  | "google"
  | "azure_openai"
  | "openai_compatible"
  | "bedrock"
  | "vertex";

export type LlmProvider = {
  id: string;
  label: string;
  provider: LlmProviderKind;
  model: string;
  base_url?: string | null;
  azure_deployment?: string | null;
  azure_api_version?: string | null;
  extra?: Record<string, unknown> | null;
  key_set: boolean;
  key_hint?: string | null;
  is_active: boolean;
  created_at: string;
};

export type LlmProviderInput = {
  label: string;
  provider: LlmProviderKind;
  model: string;
  base_url?: string;
  api_key?: string; // omit on edit to keep unchanged; "" to clear
  azure_deployment?: string;
  azure_api_version?: string;
  // Non-secret per-provider config (bedrock: region; vertex: project+location).
  extra?: Record<string, unknown>;
  // Structured secret material — bedrock AWS keys / vertex service-account JSON.
  // Never returned by the API; omit on edit to keep unchanged.
  credentials?: Record<string, unknown>;
};

export const listProviders = () => api<LlmProvider[]>("/llm-providers");
export const getCatalog = () =>
  api<{
    kinds: LlmProviderKind[];
    models: Record<string, { id: string; label: string }[]>;
  }>("/llm-providers/catalog");
export const createProvider = (body: LlmProviderInput) =>
  api<LlmProvider>("/llm-providers", { method: "POST", json: body });
export const updateProvider = (id: string, body: Partial<LlmProviderInput>) =>
  api<LlmProvider>(`/llm-providers/${id}`, { method: "PATCH", json: body });
export const deleteProvider = (id: string) =>
  api<void>(`/llm-providers/${id}`, { method: "DELETE" });
export const activateProvider = (id: string) =>
  api<LlmProvider>(`/llm-providers/${id}/activate`, { method: "POST" });
export const deactivateProvider = () =>
  api<void>("/llm-providers/deactivate", { method: "POST" });
export const testProvider = (id: string) =>
  api<{
    ok: boolean;
    latency_ms: number;
    error: string | null;
    model: string;
    sample?: string;
  }>(`/llm-providers/${id}/test`, { method: "POST" });
