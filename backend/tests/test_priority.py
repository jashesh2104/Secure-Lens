"""Tests for the priority scoring service (pure, deterministic)."""

from __future__ import annotations

from app.models.finding import Severity, SourceTool
from app.schemas.reachability import ReachabilityResult
from app.services.priority import compute_priority


def _reach(**kw) -> ReachabilityResult:
    base = dict(reachable=True, confidence="high", entry_point_kind="web_route",
                entry_point="GET /x", reason="reachable")
    base.update(kw)
    return ReachabilityResult(**base)


def test_critical_on_web_route_is_urgent():
    result = compute_priority(Severity.CRITICAL, _reach(), SourceTool.SONARQUBE)
    assert result.score >= 80
    assert result.label == "urgent"


def test_unreachable_low_severity_is_noise():
    reach = _reach(reachable=False, confidence="high", entry_point_kind="unknown",
                   entry_point=None, reason="dead code")
    result = compute_priority(Severity.LOW, reach, SourceTool.SONARQUBE)
    assert result.score < 20
    assert result.label == "noise"


def test_unreachable_beats_nothing_but_ranks_below_reachable():
    reachable = compute_priority(Severity.HIGH, _reach(), SourceTool.SONARQUBE)
    unreachable = compute_priority(
        Severity.HIGH,
        _reach(reachable=False, confidence="high", entry_point_kind="unknown",
               entry_point=None, reason="dead"),
        SourceTool.SONARQUBE,
    )
    assert reachable.score > unreachable.score


def test_module_level_secret_gets_boost():
    reach = _reach(entry_point_kind="module_top_level", entry_point="module top-level")
    result = compute_priority(Severity.HIGH, reach, SourceTool.GITLEAKS)
    assert any("module-level" in f for f in result.factors)
    assert result.score >= 70


def test_low_confidence_reach_is_discounted():
    high = compute_priority(Severity.MEDIUM, _reach(confidence="high"), SourceTool.SONARQUBE)
    low = compute_priority(Severity.MEDIUM, _reach(confidence="low"), SourceTool.SONARQUBE)
    assert low.score < high.score
