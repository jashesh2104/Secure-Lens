"""Self-verifying fixes: generate a patch, then prove it before showing it.

The pipeline is deliberately three steps so ``verified=True`` is trustworthy:

1. **Generate** — the configured LLM (grounded in the finding + KB context)
   returns the full corrected file. Whole-file output avoids brittle diffs.
2. **Apply in a sandbox** — the patch is written to a temp copy, never the real
   repo, so verification has zero blast radius.
3. **Verify independently** — the patched file must (a) still parse and (b) pass
   a scanner/heuristic recheck showing the vulnerable pattern is gone. Only when
   both hold do we mark the fix ``verified``.

The LLM call is isolated in :func:`generate_fix` so tests can mock it exactly
like the triage agent. Verification never trusts the model's word — it re-checks.
"""

from __future__ import annotations

import ast
import difflib
import logging
import os
import re
import shutil
import subprocess
import tempfile

from langchain_core.prompts import ChatPromptTemplate

from app.models.finding import Finding, SourceTool
from app.schemas.fix import (
    ProposedFix,
    VerificationStep,
    VerifiedFixResult,
)
from app.services.llm import get_chat_model, llm_available, unavailable_reason
from app.services.rag_engine import retrieve

logger = logging.getLogger("securelens.verified_fix")

_MAX_FILE_CHARS = 12_000  # keep the prompt within a sane token budget

_SYSTEM = (
    "You are a secure-coding assistant. You are given the full contents of a "
    "file and one security finding in it. Return the COMPLETE corrected file "
    "that removes the vulnerability while preserving behavior and public APIs. "
    "Prefer minimal, idiomatic fixes (parameterized queries, safe subprocess "
    "calls without shell, removing hardcoded secrets in favor of env vars, "
    "input validation). Do not add commentary outside the code."
)
_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _SYSTEM),
    ("human",
     "Finding:\n- tool: {tool}\n- rule: {rule}\n- file: {file}:{line}\n"
     "- message: {message}\n\nKnowledge-base context:\n{context}\n\n"
     "Current file contents:\n```\n{content}\n```"),
])

# Heuristic sink patterns per vulnerability category. Used to confirm a SAST fix
# removed the dangerous construct when re-running the full SAST engine in a
# verify loop is impractical. Keyed off rule id / message keywords.
_CATEGORY_PATTERNS: dict[str, re.Pattern[str]] = {
    "command_injection": re.compile(
        r"os\.system\s*\(|subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True|"
        r"os\.popen\s*\(", re.IGNORECASE),
    "sql_injection": re.compile(
        r"(?:execute|executemany)\s*\(\s*[^),]*(?:\+|%|\.format\(|f['\"])", re.IGNORECASE),
    "code_injection": re.compile(r"\beval\s*\(|\bexec\s*\(", re.IGNORECASE),
}

_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "command_injection": ("command inject", "os command", "cwe-78", "cwe-77", "s4721", "shell"),
    "sql_injection": ("sql inject", "cwe-89", "s3649", "query"),
    "code_injection": ("code inject", "cwe-94", "eval", "exec", "deserial"),
}


def _categorize(finding: Finding) -> str | None:
    """Map a finding to a heuristic category via its rule id / message."""
    haystack = f"{finding.rule_id} {finding.message}".lower()
    for category, keywords in _CATEGORY_KEYWORDS.items():
        if any(k in haystack for k in keywords):
            return category
    return None


def _resolve_file(repo_path: str, rel_path: str) -> str | None:
    """Return the absolute path of a finding's file if it exists in the repo."""
    candidate = os.path.normpath(os.path.join(repo_path, rel_path))
    return candidate if os.path.isfile(candidate) else None


def generate_fix(finding: Finding, original_content: str) -> ProposedFix:
    """Ask the LLM for the corrected file (raises if LLM unset). Mockable in tests."""
    if not llm_available():
        raise RuntimeError(unavailable_reason())
    query = f"{finding.rule_id} {finding.message} secure fix"
    context = "\n\n---\n\n".join(retrieve(query, k=3)) or "No context found."
    llm = get_chat_model()
    chain = _PROMPT | llm.with_structured_output(ProposedFix)
    return chain.invoke({
        "tool": finding.source_tool.value,
        "rule": finding.rule_id,
        "file": finding.file_path,
        "line": finding.line_number or 0,
        "message": finding.message,
        "context": context,
        "content": original_content[:_MAX_FILE_CHARS],
    })


def _gitleaks_clean(content: str, basename: str) -> VerificationStep:
    """Re-run gitleaks on the patched content in a sandbox; pass if no secrets."""
    binary = shutil.which("gitleaks")
    if not binary:
        return VerificationStep(
            name="secret_rescan", passed=False,
            detail="gitleaks binary not available to verify; fix left unverified.",
        )
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, basename)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(content)
        report = os.path.join(tmp, "report.json")
        try:
            subprocess.run(
                [binary, "dir", tmp, "--report-format", "json",
                 "--report-path", report, "--no-banner"],
                capture_output=True, text=True, timeout=60,
            )
            data = ""
            if os.path.isfile(report):
                with open(report, encoding="utf-8") as fh:
                    data = fh.read().strip()
            leaked = bool(data and data != "[]")
        except (subprocess.SubprocessError, OSError) as exc:
            return VerificationStep(
                name="secret_rescan", passed=False,
                detail=f"gitleaks re-scan failed: {exc}",
            )
    return VerificationStep(
        name="secret_rescan", passed=not leaked,
        detail="No secrets detected in patched file." if not leaked
        else "Patched file still contains a detectable secret.",
    )


def _pattern_gone(finding: Finding, content: str) -> VerificationStep:
    """Confirm the vulnerable sink pattern no longer appears in the patched file."""
    category = _categorize(finding)
    if category is None:
        return VerificationStep(
            name="pattern_recheck", passed=False,
            detail="No known sink pattern for this rule; cannot auto-verify.",
        )
    still = _CATEGORY_PATTERNS[category].search(content) is not None
    return VerificationStep(
        name="pattern_recheck", passed=not still,
        detail=(f"'{category}' sink pattern no longer present." if not still
                else f"'{category}' sink pattern still present after fix."),
    )


def _syntax_ok(rel_path: str, content: str) -> VerificationStep:
    """Python files must still parse; non-Python files skip this check."""
    if not rel_path.endswith(".py"):
        return VerificationStep(name="syntax", passed=True,
                                detail="Non-Python file; syntax check skipped.")
    try:
        ast.parse(content)
    except SyntaxError as exc:
        return VerificationStep(name="syntax", passed=False,
                                detail=f"Patched file does not parse: {exc}")
    return VerificationStep(name="syntax", passed=True, detail="Patched file parses.")


def verify_fix(finding: Finding, original: str, patched: str) -> VerifiedFixResult:
    """Run independent checks against a patched file and build the result."""
    rel = finding.file_path
    basename = os.path.basename(rel) or "patched.txt"

    steps = [_syntax_ok(rel, patched)]
    if finding.source_tool == SourceTool.GITLEAKS:
        steps.append(_gitleaks_clean(patched, basename))
    else:
        steps.append(_pattern_gone(finding, patched))

    verified = all(s.passed for s in steps)
    diff = "".join(difflib.unified_diff(
        original.splitlines(keepends=True), patched.splitlines(keepends=True),
        fromfile=f"a/{rel}", tofile=f"b/{rel}",
    ))
    status = "verified" if verified else "unverified"
    return VerifiedFixResult(
        status=status, verified=verified, unified_diff=diff,
        patched_file_content=patched, steps=steps,
    )


def propose_and_verify_fix(finding: Finding, repo_path: str) -> VerifiedFixResult:
    """End-to-end: read the file, generate a fix, apply in a sandbox, verify."""
    abs_path = _resolve_file(repo_path, finding.file_path)
    if abs_path is None:
        return VerifiedFixResult(
            status="failed", verified=False,
            fix_explanation=f"Source file '{finding.file_path}' not found in repo.",
            steps=[VerificationStep(name="locate_file", passed=False,
                                    detail="File not found; cannot generate a fix.")],
        )
    with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
        original = fh.read()

    proposed = generate_fix(finding, original)
    result = verify_fix(finding, original, proposed.patched_file_content)
    result.fix_explanation = proposed.fix_explanation
    return result
