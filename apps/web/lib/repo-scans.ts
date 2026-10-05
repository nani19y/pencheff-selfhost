// Shared mapping for repository (SAST) scans so the dashboard and the
// assessments list render them identically. RepoScan rows come from
// GET /repos/scans and must be normalised into the same shape as DAST
// Scan rows (from GET /scans) before the two lists are merged.

export type RepoScanRow = {
  id: string;
  repository_id: string;
  status: string;
  summary: Record<string, number | string> | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
};

/** Severity-count → letter grade, matching the DAST grade buckets. */
export function calculateRepoGrade(
  summary: Record<string, number | string> | null,
): string {
  if (!summary) return "A";
  const crit = Number(summary.critical) || 0;
  const high = Number(summary.high) || 0;
  const med = Number(summary.medium) || 0;
  const low = Number(summary.low) || 0;

  if (crit > 0) return "F";
  if (high > 0) return "D";
  if (med > 0) return "C";
  if (low > 0) return "B";
  return "A";
}

/** Normalise a RepoScan into a Scan-shaped row keyed to its Target. */
export function mapRepoScanToScan(
  r: RepoScanRow,
  targets: Array<{ id: string; repository_id?: string | null }>,
) {
  const target = targets.find((tg) => tg.repository_id === r.repository_id);
  const status = r.status === "succeeded" ? "done" : r.status;
  return {
    id: r.id,
    target_id: target?.id || "",
    status,
    progress_pct: r.status === "running" ? 50 : 100,
    grade: calculateRepoGrade(r.summary),
    score: null,
    profile: "Deep",
    summary: r.summary || null,
    started_at: r.started_at,
    finished_at: r.completed_at,
    created_at: r.created_at,
    repository_id: r.repository_id,
  };
}
