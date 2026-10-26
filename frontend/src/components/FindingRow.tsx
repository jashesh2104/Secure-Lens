import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Finding } from "../api";
import { SeverityBadge } from "./SeverityBadge";
import { PriorityBadge } from "./PriorityBadge";
import { ReachabilityBadge } from "./ReachabilityBadge";

export function FindingRow({ finding }: { finding: Finding }) {
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ["findings"] });
  const triage = useMutation({
    mutationFn: () => api.triage(finding.id),
    onSuccess: invalidate,
  });
  const fix = useMutation({
    mutationFn: () => api.fix(finding.id),
    onSuccess: invalidate,
  });
  const t = finding.triage_result;
  const vf = finding.verified_fix;

  return (
    <div className="border border-slate-800 rounded p-3 mb-2 bg-slate-900">
      <div className="flex items-center gap-2 flex-wrap">
        {finding.priority && (
          <PriorityBadge label={finding.priority.label} score={finding.priority.score} />
        )}
        <SeverityBadge value={t?.reranked_severity ?? finding.normalized_severity} />
        {finding.reachability && (
          <ReachabilityBadge reachability={finding.reachability} />
        )}
        <span className="text-xs text-slate-400">{finding.source_tool}</span>
        <span className="font-mono text-sm">{finding.rule_id}</span>
        <span className="text-xs text-slate-400">
          {finding.file_path}:{finding.line_number ?? "?"}
        </span>
        <div className="ml-auto flex gap-2">
          <button
            onClick={() => triage.mutate()}
            disabled={triage.isPending}
            className="text-xs px-2 py-1 rounded bg-indigo-600 disabled:opacity-50"
          >
            {triage.isPending ? "Triaging..." : t ? "Re-triage" : "Triage"}
          </button>
          <button
            onClick={() => fix.mutate()}
            disabled={fix.isPending}
            className="text-xs px-2 py-1 rounded bg-emerald-700 disabled:opacity-50"
          >
            {fix.isPending ? "Fixing..." : "Verified fix"}
          </button>
        </div>
      </div>

      <p className="text-sm mt-2">{finding.message}</p>

      {finding.priority && (
        <p className="text-xs text-slate-500 mt-1">
          Priority: {finding.priority.factors.join("  ·  ")}
        </p>
      )}

      {t && (
        <div className="mt-3 text-sm space-y-1 border-t border-slate-800 pt-2">
          <p><b>Why:</b> {t.explanation}</p>
          <p><b>Exploit:</b> {t.exploit_scenario}</p>
          <p><b>Fix:</b> {t.fix_suggestion}</p>
          <p className="text-xs text-slate-400">Refs: {t.references.join(", ")}</p>
        </div>
      )}

      {vf && (
        <div className="mt-3 text-sm border-t border-slate-800 pt-2">
          <p className="flex items-center gap-2">
            <span
              className={`px-2 py-0.5 rounded text-xs font-semibold ${
                vf.verified ? "bg-emerald-700 text-white" : "bg-slate-700 text-slate-200"
              }`}
            >
              {vf.verified ? "✓ VERIFIED FIX" : "PROPOSED (unverified)"}
            </span>
            <span className="text-slate-300">{vf.fix_explanation}</span>
          </p>
          <ul className="mt-1 text-xs text-slate-400 list-disc pl-5">
            {vf.steps.map((s) => (
              <li key={s.name}>
                {s.passed ? "✓" : "✗"} {s.name}: {s.detail}
              </li>
            ))}
          </ul>
          {vf.unified_diff && (
            <pre className="mt-2 text-xs bg-slate-950 border border-slate-800 rounded p-2 overflow-x-auto whitespace-pre">
              {vf.unified_diff}
            </pre>
          )}
        </div>
      )}

      {triage.isError && (
        <p className="text-xs text-red-400 mt-1">Triage failed (set GROQ_API_KEY).</p>
      )}
      {fix.isError && (
        <p className="text-xs text-red-400 mt-1">Fix failed (set GROQ_API_KEY).</p>
      )}
    </div>
  );
}
