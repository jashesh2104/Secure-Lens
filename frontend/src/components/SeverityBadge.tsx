import type { Severity } from "../api";

const COLORS: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-slate-500 text-white",
};

export function SeverityBadge({ value }: { value: Severity }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${COLORS[value]}`}>
      {value.toUpperCase()}
    </span>
  );
}
