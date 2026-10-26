"""Unit test for the RAG triage agent.

We mock the Groq LLM call (ChatGroq) and the knowledge-base retrieval so no API
key, network, or Chroma store is needed. The mocked structured-output runnable
returns a TriageResult, and we assert the agent hands back a valid schema object
with all required fields populated.
"""

from unittest.mock import MagicMock, patch

from langchain_core.runnables import RunnableLambda

from app.models.finding import Finding, Severity, SourceTool
from app.schemas.triage import TriageResult
from app.services import triage_agent


def _finding() -> Finding:
    """A minimal, un-persisted Finding to feed the triage agent."""
    return Finding(
        source_tool=SourceTool.SONARQUBE,
        severity="MAJOR",
        normalized_severity=Severity.HIGH,
        rule_id="python:S3649",
        file_path="app/db.py",
        line_number=42,
        message="User input concatenated into SQL query.",
    )


def test_triage_finding_returns_valid_triage_result(monkeypatch):
    expected = TriageResult(
        reranked_severity=Severity.CRITICAL,
        explanation="Untrusted input is concatenated into a SQL statement.",
        exploit_scenario="An attacker submits ' OR '1'='1 to bypass the query.",
        fix_suggestion="Use parameterized queries / bound parameters.",
        references=["cwe_089_sql_injection", "owasp_a03_injection"],
    )

    # No real API key, network, or Chroma store.
    monkeypatch.setattr(triage_agent, "llm_available", lambda: True)
    monkeypatch.setattr(triage_agent, "retrieve", lambda *a, **k: ["kb context"])

    # Mock the chat model so structured output yields our TriageResult.
    fake_llm = MagicMock()
    fake_llm.with_structured_output.return_value = RunnableLambda(lambda _: expected)

    with patch.object(triage_agent, "get_chat_model", return_value=fake_llm):
        result = triage_agent.triage_finding(_finding())

    # Matches the Pydantic schema.
    assert isinstance(result, TriageResult)

    # All required fields present and non-empty.
    assert result.reranked_severity
    assert result.explanation.strip()
    assert result.exploit_scenario.strip()
    assert result.fix_suggestion.strip()
    assert result.references
