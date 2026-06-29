"""Tests for the PR comment renderer and merge gate."""

from app.models.finding import Finding, Severity, SourceTool
from app.services import github_pr


def _f(sev: Severity) -> Finding:
    return Finding(source_tool=SourceTool.GITLEAKS, severity="s",
                   normalized_severity=sev, rule_id="r", file_path="a.py",
                   line_number=1, message="m")


def test_gate_blocks_on_critical():
    assert github_pr.severity_gate([_f(Severity.CRITICAL)]) is True


def test_gate_allows_without_critical():
    assert github_pr.severity_gate([_f(Severity.HIGH), _f(Severity.LOW)]) is False


def test_comment_empty():
    assert "No security findings" in github_pr.render_comment([])


def test_comment_lists_and_blocks():
    body = github_pr.render_comment([_f(Severity.CRITICAL)])
    assert "Merge blocked" in body
