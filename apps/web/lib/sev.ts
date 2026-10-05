export const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export type Severity = (typeof SEV_ORDER)[number];

export const SEV_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info.",
};

export const SEV_COLOR: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

export const SEV_HEX: Record<Severity, string> = {
  critical: "#C00000",
  high: "#E06666",
  medium: "#E69138",
  low: "#6FA8DC",
  info: "#B7B7B7",
};

export const SEV_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function isSeverity(s: string): s is Severity {
  return (SEV_ORDER as readonly string[]).includes(s);
}

export function normalizeSeverity(s: string | null | undefined): Severity {
  const v = (s || "info").toLowerCase();
  return isSeverity(v) ? v : "info";
}
