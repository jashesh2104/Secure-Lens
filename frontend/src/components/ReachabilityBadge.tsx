import type { Reachability } from "../api";

const KIND_LABEL: Record<Reachability["entry_point_kind"], string> = {
  web_route: "Web route",
  cli_main: "CLI/main",
  module_top_level: "Module load",
  public_function: "Public fn",
  unknown: "Unknown",
};

export function ReachabilityBadge({ reachability }: { reachability: Reachability }) {
  const { reachable, entry_point_kind, entry_point, call_path, reason } = reachability;
  const color = reachable
    ? entry_point_kind === "web_route"
      ? "bg-red-900 text-red-200 border-red-700"
      : "bg-amber-900 text-amber-200 border-amber-700"
    : "bg-slate-800 text-slate-400 border-slate-700";
  const tip = [
    reason,
    call_path.length ? `Path: ${call_path.join(" → ")}` : "",
  ]
    .filter(Boolean)
    .join("  |  ");

  return (
    <span title={tip} className={`px-2 py-0.5 rounded text-xs border ${color}`}>
      {reachable ? "⮕ reachable" : "∅ not reachable"}
      {" · "}
      {KIND_LABEL[entry_point_kind]}
      {reachable && entry_point ? ` (${entry_point})` : ""}
    </span>
  );
}
