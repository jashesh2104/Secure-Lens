"""Triage agent: RAG-grounded vulnerability triage via Groq.

For a given finding we (1) retrieve relevant OWASP/CWE passages, (2) feed them
plus the finding's code context to Groq, and (3) get back a structured
TriageResult. Grounding the model in the knowledge base — rather than trusting
its parametric memory — is the core of SecureLens: explanations cite our curated
corpus, and the model re-ranks severity with that context.

Requires GROQ_API_KEY. The output is constrained to the TriageResult schema via
LangChain's structured-output binding so we always get valid JSON to persist.
"""

from __future__ import annotations

from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq

from app.config import get_settings
from app.models.finding import Finding
from app.schemas.triage import TriageResult
from app.services.rag_engine import retrieve

settings = get_settings()

_SYSTEM = (
    "You are a security triage assistant. Use ONLY the provided knowledge-base "
    "context to explain the finding, describe a realistic exploit, and suggest "
    "a concrete fix. Re-rank severity to one of critical/high/medium/low based "
    "on the context. Cite the OWASP/CWE doc names you used in references. Do not "
    "invent CVEs, metrics, or facts not supported by the context."
)
_PROMPT = ChatPromptTemplate.from_messages([
    ("system", _SYSTEM),
    ("human",
     "Finding:\n- tool: {tool}\n- rule: {rule}\n- severity: {severity}\n"
     "- file: {file}:{line}\n- message: {message}\n\n"
     "Knowledge-base context:\n{context}"),
])


def triage_finding(finding: Finding) -> TriageResult:
    """Produce a grounded TriageResult for one finding (raises if no API key)."""
    if not settings.groq_api_key:
        raise RuntimeError("GROQ_API_KEY not set; cannot run triage.")

    query = f"{finding.rule_id} {finding.message}"
    context = "\n\n---\n\n".join(retrieve(query, k=4)) or "No context found."

    llm = ChatGroq(model=settings.groq_model, temperature=0,
                   api_key=settings.groq_api_key)
    chain = _PROMPT | llm.with_structured_output(TriageResult)
    return chain.invoke({
        "tool": finding.source_tool.value,
        "rule": finding.rule_id,
        "severity": finding.normalized_severity.value,
        "file": finding.file_path,
        "line": finding.line_number or 0,
        "message": finding.message,
        "context": context,
    })
