// Typed API client. In dev, Vite proxies "/api" -> backend; in prod the SPA is
// served by the same nginx that reverse-proxies "/api" to FastAPI.
const BASE = "/api";

export type Severity = "critical" | "high" | "medium" | "low";

export interface Finding {
  id: number;
  scan_id: number;
  source_tool: "sonarqube" | "gitleaks";
  severity: string;
  normalized_severity: Severity;
  rule_id: string;
  file_path: string;
  line_number: number | null;
  message: string;
  status: "new" | "triaged";
  triage_result: TriageResult | null;
}

export interface TriageResult {
  reranked_severity: Severity;
  explanation: string;
  exploit_scenario: string;
  fix_suggestion: string;
  references: string[];
}

export interface Scan {
  id: number;
  repo_id: number;
  status: "pending" | "running" | "completed" | "failed";
  started_at: string | null;
  completed_at: string | null;
  tool_versions: Record<string, string> | null;
  findings: Finding[];
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export const api = {
  createScan: (name: string, url_or_path: string) =>
    req<Scan>("/scan", { method: "POST", body: JSON.stringify({ name, url_or_path }) }),
  getScan: (id: number) => req<Scan>(`/scan/${id}`),
  listFindings: (scanId?: number) =>
    req<Finding[]>(`/findings${scanId ? `?scan_id=${scanId}` : ""}`),
  triage: (id: number) => req<Finding>(`/findings/${id}/triage`, { method: "POST" }),
};
