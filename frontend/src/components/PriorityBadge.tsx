import type { PriorityLabel } from "../api";

const COLORS: Record<PriorityLabel, string> = {
  urgent: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  moderate: "bg-yellow-500 text-black",
  low: "bg-slate-500 text-white",
  noise: "bg-slate-700 text-slate-300",
};

export function PriorityBadge({ label, score }: { label: PriorityLabel; score: number }) {
  return (
    <span
      title={`Priority score ${score}/100 — severity fused with codebase reachability`}
      className={`px-2 py-0.5 rounded text-xs font-bold ${COLORS[label]}`}
    >
      {label.toUpperCase()} {score}
    </span>
  );
}
