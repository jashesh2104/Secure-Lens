"""GitHub PR integration: post a findings comment and compute the merge gate.

Used by the CI workflow. Two pieces, kept separate so they're testable:
  - render_comment(): turns findings into a markdown summary.
  - severity_gate(): decides whether critical findings should block merge.
The actual HTTP post is a thin wrapper so tests can run without network.
"""

from __future__ import annotations

import os

import requests

from app.models.finding import Finding, Severity

_BLOCKING = {Severity.CRITICAL}


def severity_gate(findings: list[Finding]) -> bool:
    """Return True if merge should be BLOCKED (any blocking-severity finding)."""
    return any(f.normalized_severity in _BLOCKING for f in findings)


def render_comment(findings: list[Finding]) -> str:
    """Render a PR comment summarizing findings, worst severity first."""
    if not findings:
        return "## SecureLens\n\nNo security findings. ✅"
    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    rows = sorted(findings, key=lambda f: order[f.normalized_severity])
    lines = ["## SecureLens findings\n", "| Severity | Tool | Rule | Location |", "|---|---|---|---|"]
    for f in rows:
        loc = f"{f.file_path}:{f.line_number or '?'}"
        lines.append(f"| {f.normalized_severity.value} | {f.source_tool.value} | {f.rule_id} | {loc} |")
    if severity_gate(findings):
        lines.append("\n**Merge blocked: critical findings present.**")
    return "\n".join(lines)


def post_pr_comment(repo: str, pr_number: int, body: str,
                    token: str | None = None) -> int:
    """Post a comment to a PR. repo is 'owner/name'. Returns HTTP status."""
    token = token or os.environ.get("GITHUB_TOKEN", "")
    resp = requests.post(
        f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments",
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json"},
        json={"body": body},
        timeout=30,
    )
    return resp.status_code
