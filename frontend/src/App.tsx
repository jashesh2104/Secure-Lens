import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { FindingRow } from "./components/FindingRow";

export default function App() {
  const qc = useQueryClient();
  const [name, setName] = useState("demo");
  const [path, setPath] = useState("../sample_vuln");

  const findings = useQuery({
    queryKey: ["findings"],
    queryFn: () => api.listFindings(),
    refetchInterval: 5000, // poll so a running scan's results stream in
  });

  const startScan = useMutation({
    mutationFn: () => api.createScan(name, path),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });

  return (
    <div className="max-w-4xl mx-auto p-6">
      <h1 className="text-2xl font-bold mb-1">SecureLens</h1>
      <p className="text-slate-400 mb-4 text-sm">AI-augmented DevSecOps triage</p>

      <div className="flex gap-2 mb-6">
        <input value={name} onChange={(e) => setName(e.target.value)}
          className="bg-slate-800 px-2 py-1 rounded text-sm" placeholder="repo name" />
        <input value={path} onChange={(e) => setPath(e.target.value)}
          className="bg-slate-800 px-2 py-1 rounded text-sm flex-1" placeholder="path or URL" />
        <button onClick={() => startScan.mutate()} disabled={startScan.isPending}
          className="px-3 py-1 rounded bg-emerald-600 text-sm disabled:opacity-50">
          {startScan.isPending ? "Scanning..." : "Run scan"}
        </button>
      </div>

      {findings.isLoading && <p>Loading...</p>}
      {findings.data?.length === 0 && <p className="text-slate-400">No findings yet.</p>}
      {findings.data?.map((f) => <FindingRow key={f.id} finding={f} />)}
    </div>
  );
}
