"""Triage agent: RAG-grounded vulnerability triage.

For a given finding we (1) retrieve relevant OWASP/CWE passages, (2) feed them
plus the finding's code context to the configured LLM, and (3) get back a
structured TriageResult. Grounding the model in the knowledge base — rather than
trusting its parametric memory — is the core of SecureLens: explanations cite
our curated corpus, and the model re-ranks severity with that context.

The model is chosen by ``LLM_PROVIDER`` (see app.services.llm); the output is
constrained to the TriageResult schema via LangChain's structured-output
binding so we always get valid JSON to persist.
"""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate

from app.models.finding import Finding
from app.schemas.triage import TriageResult
from app.services.llm import get_chat_model, llm_available, unavailable_reason
from app.services.rag_engine import retrieve

_SYSTEM = (
    "You are a security triage assistant. Use ONLY the provided knowledge-base "
    "context to explain the finding, describe a realistic exploit, and suggest "
    "a concrete fix. Re-rank severity to one of critical/high/medium/low based "
    "on the context AND the reachability signal: a vulnerability reachable from "
    "an internet-facing web route is more severe than the same pattern in dead "
    "or unreachable code, which you should down-rank. Cite the OWASP/CWE doc "
    "names you used in references. Do not invent CVEs, metrics, or facts not "
    "supported by the context."
)
_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _SYSTEM),
    ("human",
     "Finding:\n- tool: {tool}\n- rule: {rule}\n- severity: {severity}\n"
     "- file: {file}:{line}\n- message: {message}\n\n"
     "Reachability (from static analysis of this repo):\n{reachability}\n\n"
     "Knowledge-base context:\n{context}"),
])


def _reachability_summary(finding: Finding) -> str:
    """One-line, model-friendly summary of the finding's reachability verdict."""
    reach = finding.reachability or {}
    if not reach:
        return "unknown (not analyzed)"
    verdict = "REACHABLE" if reach.get("reachable") else "NOT reachable"
    kind = reach.get("entry_point_kind", "unknown")
    entry = reach.get("entry_point") or "n/a"
    conf = reach.get("confidence", "low")
    return (
        f"{verdict} (confidence={conf}, kind={kind}, entry_point={entry}). "
        f"{reach.get('reason', '')}"
    )


def triage_finding(finding: Finding) -> TriageResult:
    """Produce a grounded TriageResult for one finding (raises if LLM unset)."""
    if not llm_available():
        raise RuntimeError(unavailable_reason())

    query = f"{finding.rule_id} {finding.message}"
    context = "\n\n---\n\n".join(retrieve(query, k=4)) or "No context found."

    llm = get_chat_model()
    chain = _PROMPT | llm.with_structured_output(TriageResult)
    return chain.invoke({
        "tool": finding.source_tool.value,
        "rule": finding.rule_id,
        "severity": finding.normalized_severity.value,
        "file": finding.file_path,
        "line": finding.line_number or 0,
        "message": finding.message,
        "reachability": _reachability_summary(finding),
        "context": context,
    })
