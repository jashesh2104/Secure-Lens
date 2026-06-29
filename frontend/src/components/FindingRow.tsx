import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Finding } from "../api";
import { SeverityBadge } from "./SeverityBadge";

export function FindingRow({ finding }: { finding: Finding }) {
  const qc = useQueryClient();
  const triage = useMutation({
    mutationFn: () => api.triage(finding.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });
  const t = finding.triage_result;

  return (
    <div className="border border-slate-800 rounded p-3 mb-2 bg-slate-900">
      <div className="flex items-center gap-3">
        <SeverityBadge value={t?.reranked_severity ?? finding.normalized_severity} />
        <span className="text-xs text-slate-400">{finding.source_tool}</span>
        <span className="font-mono text-sm">{finding.rule_id}</span>
        <span className="text-xs text-slate-400">
          {finding.file_path}:{finding.line_number ?? "?"}
        </span>
        <button
          onClick={() => triage.mutate()}
          disabled={triage.isPending}
          className="ml-auto text-xs px-2 py-1 rounded bg-indigo-600 disabled:opacity-50"
        >
          {triage.isPending ? "Triaging..." : t ? "Re-triage" : "Triage"}
        </button>
      </div>
      <p className="text-sm mt-2">{finding.message}</p>
      {t && (
        <div className="mt-3 text-sm space-y-1 border-t border-slate-800 pt-2">
          <p><b>Why:</b> {t.explanation}</p>
          <p><b>Exploit:</b> {t.exploit_scenario}</p>
          <p><b>Fix:</b> {t.fix_suggestion}</p>
          <p className="text-xs text-slate-400">Refs: {t.references.join(", ")}</p>
        </div>
      )}
      {triage.isError && <p className="text-xs text-red-400 mt-1">Triage failed (set GROQ_API_KEY).</p>}
    </div>
  );
}
