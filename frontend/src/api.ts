// Typed API client. The API base URL is read from VITE_API_BASE_URL at build
// time (see frontend/.env.example). When unset it falls back to "/api", which
// in dev Vite proxies to the backend and in prod nginx reverse-proxies to
// FastAPI.
const BASE = import.meta.env.VITE_API_BASE_URL ?? "/api";

// JWT is kept in localStorage and attached as a bearer token on every request.
// Protected routes (scan, findings, fix) 401 without it, so this is required
// for the app to function past the login screen.
const TOKEN_KEY = "securelens_token";

export const auth = {
  token: () => localStorage.getItem(TOKEN_KEY),
  setToken: (t: string) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
  isAuthed: () => Boolean(localStorage.getItem(TOKEN_KEY)),
};

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
  reachability: Reachability | null;
  priority: Priority | null;
  verified_fix: VerifiedFix | null;
}

export interface TriageResult {
  reranked_severity: Severity;
  explanation: string;
  exploit_scenario: string;
  fix_suggestion: string;
  references: string[];
}

export type PriorityLabel = "urgent" | "high" | "moderate" | "low" | "noise";

export interface Reachability {
  reachable: boolean;
  confidence: "high" | "medium" | "low";
  entry_point_kind:
    | "web_route"
    | "cli_main"
    | "module_top_level"
    | "public_function"
    | "unknown";
  entry_point: string | null;
  call_path: string[];
  enclosing_symbol: string | null;
  distance: number | null;
  reason: string;
}

export interface Priority {
  score: number;
  label: PriorityLabel;
  factors: string[];
}

export interface VerificationStep {
  name: string;
  passed: boolean;
  detail: string;
}

export interface VerifiedFix {
  status: "verified" | "unverified" | "failed";
  verified: boolean;
  fix_explanation: string;
  unified_diff: string;
  patched_file_content: string;
  steps: VerificationStep[];
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

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const token = auth.token();
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...init,
  });
  if (res.status === 401) {
    // Token missing/expired/invalid: drop it and let the app fall back to login.
    auth.clear();
    window.dispatchEvent(new Event("securelens:unauthorized"));
    throw new Error("Unauthorized — please sign in again.");
  }
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export const api = {
  register: (username: string, password: string) =>
    req<TokenResponse>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  login: (username: string, password: string) =>
    req<TokenResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  createScan: (name: string, url_or_path: string) =>
    req<Scan>("/scan", { method: "POST", body: JSON.stringify({ name, url_or_path }) }),
  getScan: (id: number) => req<Scan>(`/scan/${id}`),
  triageScan: (id: number) => req<Scan>(`/scan/${id}/triage`, { method: "POST" }),
  listFindings: (scanId?: number) =>
    req<Finding[]>(`/findings${scanId ? `?scan_id=${scanId}` : ""}`),
  triage: (id: number) => req<Finding>(`/findings/${id}/triage`, { method: "POST" }),
  fix: (id: number) => req<Finding>(`/findings/${id}/fix`, { method: "POST" }),
};
