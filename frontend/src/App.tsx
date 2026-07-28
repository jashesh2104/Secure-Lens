import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { FindingRow } from "./components/FindingRow";

export default function App() {
  const qc = useQueryClient();
  const [name, setName] = useState("demo");
  const [path, setPath] = useState("../sample_vuln");
  const [scanId, setScanId] = useState<number | null>(null);

  const findings = useQuery({
    queryKey: ["findings"],
    queryFn: () => api.listFindings(),
    refetchInterval: 5000, // poll so a running scan's results stream in
  });

  // Poll the scan record every 3s while it's pending/running; stop otherwise.
  const scan = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.getScan(scanId!),
    enabled: scanId !== null,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "pending" || status === "running" ? 3000 : false;
    },
  });

  const startScan = useMutation({
    mutationFn: () => api.createScan(name, path),
    onSuccess: (created) => {
      setScanId(created.id);
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  const triageAll = useMutation({
    mutationFn: () => api.triageScan(scanId!),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });

  const status = scan.data?.status;
  const isScanning =
    startScan.isPending || status === "pending" || status === "running";

  return (
    <div className="max-w-4xl mx-auto p-6">
      <h1 className="text-2xl font-bold mb-1">SecureLens</h1>
      <p className="text-slate-400 mb-4 text-sm">AI-augmented DevSecOps triage</p>

      <div className="flex gap-2 mb-4">
        <input value={name} onChange={(e) => setName(e.target.value)}
          className="bg-slate-800 px-2 py-1 rounded text-sm" placeholder="repo name" />
        <input value={path} onChange={(e) => setPath(e.target.value)}
          className="bg-slate-800 px-2 py-1 rounded text-sm flex-1" placeholder="path or URL" />
        <button onClick={() => startScan.mutate()} disabled={isScanning}
          className="px-3 py-1 rounded bg-emerald-600 text-sm disabled:opacity-50">
          {isScanning ? "Scanning..." : "Run scan"}
        </button>
        <button onClick={() => triageAll.mutate()}
          disabled={scanId === null || triageAll.isPending}
          className="px-3 py-1 rounded bg-indigo-600 text-sm disabled:opacity-50">
          {triageAll.isPending ? "Triaging..." : "Triage All"}
        </button>
      </div>

      {isScanning && (
        <div className="flex items-center gap-2 mb-4 text-sm text-slate-300">
          <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-slate-500 border-t-transparent" />
          <span>Scan status: {status ?? "starting"}…</span>
        </div>
      )}

      {triageAll.isSuccess && (
        <p className="mb-4 text-sm text-emerald-400">Triage complete.</p>
      )}

      {findings.isLoading && <p>Loading...</p>}
      {findings.data?.length === 0 && <p className="text-slate-400">No findings yet.</p>}
      {findings.data?.map((f) => <FindingRow key={f.id} finding={f} />)}
    </div>
  );
}
