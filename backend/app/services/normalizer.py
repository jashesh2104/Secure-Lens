"""Normalizer: collapse SonarQube + Gitleaks output into one Finding schema.

Both tools report issues in different shapes and severity vocabularies. The
rest of SecureLens (dashboard, RAG triage, PR gate) should read ONE shape, so
this module is the single translation point.

Severity mapping rationale (interview-defensible):
  SonarQube uses a 5-level scale; we fold it into our 4-level scale:
    BLOCKER  -> CRITICAL  (must fix; can break/expose the app)
    CRITICAL -> HIGH      (serious bug/vuln, fix soon)
    MAJOR    -> MEDIUM    (quality/maintainability with security relevance)
    MINOR    -> LOW
    INFO     -> LOW
  Gitleaks has no severity; a detected secret is mapped to HIGH (not CRITICAL):
  a leaked credential is serious, but real impact depends on whether it is live
  and what it grants, so we reserve CRITICAL for confirmed catastrophic issues.
  The RAG triage layer can re-rank these in Phase 2.
"""

from __future__ import annotations

from app.models.finding import Severity, SourceTool
from app.schemas.finding import FindingCreate

_SONAR_SEVERITY_MAP: dict[str, Severity] = {
    "BLOCKER": Severity.CRITICAL,
    "CRITICAL": Severity.HIGH,
    "MAJOR": Severity.MEDIUM,
    "MINOR": Severity.LOW,
    "INFO": Severity.LOW,
}
_GITLEAKS_SEVERITY = Severity.HIGH


def normalize_path(raw_path: str, repo_root: str) -> str:
    """Return a repo-relative file path.

    Gitleaks' `dir` mode reports paths like `../sample_vuln/app.py` (and can be
    absolute), while SonarQube reports repo-relative paths. This strips an exact
    `repo_root` prefix and any leading `./`/`../` segments so both tools produce
    the same `src/app.py`-style path. Backslashes are normalized to `/`.
    """
    if not raw_path:
        return raw_path
    p = raw_path.replace("\\", "/")
    root = (repo_root or "").replace("\\", "/").rstrip("/")
    if root and p.startswith(root + "/"):
        p = p[len(root) + 1:]
    parts = p.split("/")
    while parts and parts[0] in ("", ".", ".."):
        parts.pop(0)
    return "/".join(parts)


def _normalize_sonar(issue: dict, repo_root: str = "") -> FindingCreate:
    raw_sev = issue.get("severity", "MAJOR")
    # SonarQube component looks like "projectKey:src/app.py"; keep the path part.
    component = issue.get("component", "")
    file_path = component.split(":", 1)[1] if ":" in component else component
    return FindingCreate(
        source_tool=SourceTool.SONARQUBE,
        severity=raw_sev,
        normalized_severity=_SONAR_SEVERITY_MAP.get(raw_sev, Severity.MEDIUM),
        rule_id=issue.get("rule", "unknown"),
        file_path=normalize_path(file_path, repo_root),
        line_number=issue.get("line"),
        message=issue.get("message", ""),
    )


def _normalize_gitleaks(finding: dict, repo_root: str = "") -> FindingCreate:
    return FindingCreate(
        source_tool=SourceTool.GITLEAKS,
        severity="secret",
        normalized_severity=_GITLEAKS_SEVERITY,
        rule_id=finding.get("RuleID", "unknown"),
        file_path=normalize_path(finding.get("File", ""), repo_root),
        line_number=finding.get("StartLine"),
        message=finding.get("Description", "Hardcoded secret detected"),
    )


def normalize(sonar_issues: list[dict], gitleaks_findings: list[dict],
              repo_root: str = "") -> list[FindingCreate]:
    """Map raw tool output into a single list of unified findings.

    `repo_root` is the scanned path; file paths are normalized relative to it so
    both tools report consistent, repo-relative locations.
    """
    return [_normalize_sonar(i, repo_root) for i in sonar_issues] + [
        _normalize_gitleaks(f, repo_root) for f in gitleaks_findings
    ]
