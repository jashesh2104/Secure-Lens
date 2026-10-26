"""Schemas for codebase-aware reachability analysis and priority scoring.

Reachability is what separates SecureLens from a plain scanner-aggregator: for
each finding we statically decide whether the vulnerable code is actually
reachable from a real entry point (an HTTP route, a CLI ``main``, or top-level
module code) in *this* repository. A SQL-injection in a public, unauthenticated
route is a very different risk than the same pattern in dead code or a test
fixture, and the priority score reflects that.

Both shapes are persisted on ``Finding`` as JSON, so they are documented here
and validated when written/read.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# Confidence in the reachability verdict. "high" when we found explicit entry
# points and traced (or failed to trace) a call path; "low" when the repo had
# no detectable entry points so we cannot prove reach either way.
Confidence = Literal["high", "medium", "low"]

# How the vulnerable code is entered. web_route is the highest-risk kind
# (internet-exposed); module_top_level runs on import; dead_code is unreachable.
EntryPointKind = Literal[
    "web_route",
    "cli_main",
    "module_top_level",
    "public_function",
    "unknown",
]

PriorityLabel = Literal["urgent", "high", "moderate", "low", "noise"]


class ReachabilityResult(BaseModel):
    """Whether a finding's code is reachable from an entry point in this repo."""

    reachable: bool
    confidence: Confidence
    entry_point_kind: EntryPointKind
    # Human-readable entry point, e.g. "POST /users -> get_user".
    entry_point: str | None = None
    # Call path from entry point to the vulnerable symbol (function names).
    call_path: list[str] = Field(default_factory=list)
    # The function that contains the finding, or None for module-level code.
    enclosing_symbol: str | None = None
    # Distance (edges) from the entry point to the finding; 0 == at the entry.
    distance: int | None = None
    reason: str = ""


class PriorityResult(BaseModel):
    """A single, codebase-aware priority score (0-100) with its rationale.

    This is the number a developer should sort by: it fuses the finding's
    severity with whether the code is actually reachable and internet-exposed,
    so noise (unreachable/dead code) sinks and real, exposed risk rises.
    """

    score: int = Field(ge=0, le=100)
    label: PriorityLabel
    # Ordered, human-readable contributions, e.g. "+45 reachable from web route".
    factors: list[str] = Field(default_factory=list)
