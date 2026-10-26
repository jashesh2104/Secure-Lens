"""Priority scoring: fuse severity with codebase-aware reachability.

The single number a developer should sort by. A finding's raw severity is only
half the story; the other half is whether the vulnerable code is actually
reachable from an internet-facing entry point in *this* repo. This module
combines both into a 0-100 ``PriorityResult`` with a transparent breakdown of
every factor, so the ranking is explainable rather than a black box.

Pure and deterministic: no LLM, no network. Given the same inputs it always
returns the same score, which is exactly what a triage queue needs.
"""

from __future__ import annotations

from app.models.finding import Severity, SourceTool
from app.schemas.reachability import PriorityResult, ReachabilityResult

# Base contribution from normalized severity.
_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 55,
    Severity.HIGH: 40,
    Severity.MEDIUM: 22,
    Severity.LOW: 10,
}

# How much reachability moves the score. web_route is highest because it is
# internet-exposed; unreachable code is pushed down hard so noise sinks.
_REACH_BONUS: dict[str, int] = {
    "web_route": 45,
    "cli_main": 30,
    "module_top_level": 30,
    "public_function": 12,
    "unknown": 0,
}


def compute_priority(
    severity: Severity,
    reachability: ReachabilityResult,
    source_tool: SourceTool | None = None,
) -> PriorityResult:
    """Return a 0-100 priority score with an explainable factor breakdown."""
    factors: list[str] = []

    base = _SEVERITY_WEIGHT.get(severity, 20)
    score = base
    factors.append(f"+{base} {severity.value} severity")

    if reachability.reachable:
        bonus = _REACH_BONUS.get(reachability.entry_point_kind, 0)
        # Low-confidence reach (no entry points detected) gets a discounted bonus
        # so we neither over-trust nor suppress it.
        if reachability.confidence == "low":
            bonus = bonus // 2
        if bonus:
            score += bonus
            label = reachability.entry_point or reachability.entry_point_kind
            factors.append(f"+{bonus} reachable from {reachability.entry_point_kind} ({label})")
    else:
        # Not reachable from any entry point (dead code / test / helper): this is
        # the noise-suppression that makes the queue trustworthy.
        penalty = -30 if reachability.confidence == "high" else -22
        score += penalty
        factors.append(f"{penalty} not reachable ({reachability.reason.split('.')[0].lower()})")

    # A hardcoded secret that lives in module-level code is live the moment the
    # module loads; nudge those up regardless of call-graph reach.
    if source_tool == SourceTool.GITLEAKS and reachability.entry_point_kind == "module_top_level":
        score += 8
        factors.append("+8 secret in module-level code (loaded on import)")

    score = max(0, min(100, score))
    return PriorityResult(score=score, label=_label_for(score), factors=factors)


def _label_for(score: int) -> str:
    if score >= 80:
        return "urgent"
    if score >= 60:
        return "high"
    if score >= 40:
        return "moderate"
    if score >= 20:
        return "low"
    return "noise"
