"""Tests for the self-verifying fix pipeline.

The LLM boundary (``generate_fix``) is mocked exactly like the triage agent, so
no API key or network is needed. Verification itself is exercised for real: it
must reject a patch that still contains the sink or fails to parse, and accept a
patch that genuinely removes the vulnerable construct.
"""

from __future__ import annotations

from app.models.finding import Finding, Severity, SourceTool
from app.schemas.fix import ProposedFix
from app.services import verified_fix

_VULN = "import os\n\n\ndef ping(host):\n    os.system('ping ' + host)\n"
_FIXED = (
    "import subprocess\n\n\ndef ping(host):\n"
    "    subprocess.run(['ping', host], check=True)\n"
)


def _cmd_injection_finding() -> Finding:
    return Finding(
        source_tool=SourceTool.SONARQUBE,
        severity="CRITICAL",
        normalized_severity=Severity.CRITICAL,
        rule_id="python:S4721",
        file_path="app.py",
        line_number=5,
        message="OS command injection (CWE-78).",
    )


def test_verify_accepts_a_real_fix():
    result = verified_fix.verify_fix(_cmd_injection_finding(), _VULN, _FIXED)
    assert result.verified is True
    assert result.status == "verified"
    assert result.unified_diff  # a diff was produced
    assert all(s.passed for s in result.steps)


def test_verify_rejects_patch_that_keeps_the_sink():
    # "Fix" that changed nothing meaningful — os.system is still there.
    result = verified_fix.verify_fix(_cmd_injection_finding(), _VULN, _VULN)
    assert result.verified is False
    assert any(s.name == "pattern_recheck" and not s.passed for s in result.steps)


def test_verify_rejects_syntactically_broken_patch():
    broken = "def ping(host)\n    return host\n"  # missing colon
    result = verified_fix.verify_fix(_cmd_injection_finding(), _VULN, broken)
    assert result.verified is False
    assert any(s.name == "syntax" and not s.passed for s in result.steps)


def test_propose_and_verify_reads_file_and_verifies(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(_VULN, encoding="utf-8")
    monkeypatch.setattr(
        verified_fix, "generate_fix",
        lambda finding, content: ProposedFix(
            patched_file_content=_FIXED, fix_explanation="Use subprocess without shell."
        ),
    )

    result = verified_fix.propose_and_verify_fix(_cmd_injection_finding(), str(tmp_path))

    assert result.verified is True
    assert result.fix_explanation == "Use subprocess without shell."


def test_propose_and_verify_reports_missing_file(tmp_path):
    result = verified_fix.propose_and_verify_fix(_cmd_injection_finding(), str(tmp_path))
    assert result.status == "failed"
    assert result.verified is False


def test_secret_rescan_without_binary_is_honestly_unverified(monkeypatch):
    monkeypatch.setattr(verified_fix.shutil, "which", lambda _: None)
    finding = Finding(
        source_tool=SourceTool.GITLEAKS, severity="secret",
        normalized_severity=Severity.HIGH, rule_id="aws-access-token",
        file_path="config.py", line_number=1, message="Hardcoded secret detected",
    )
    result = verified_fix.verify_fix(finding, "KEY='x'\n", "KEY=os.environ['KEY']\n")
    # Without gitleaks we cannot prove the secret is gone, so we do NOT claim verified.
    assert result.verified is False
    assert any(s.name == "secret_rescan" for s in result.steps)
