"""TriageResult schema — the RAG pipeline's output (populated in Phase 2).

Defined now so the Finding.triage_result JSON column has a documented shape the
whole team can rely on. Stored as JSON for flexibility; validated against this
schema when written/read so it stays consistent.
"""

from app.models.finding import Severity

from pydantic import BaseModel, Field


class TriageResult(BaseModel):
    reranked_severity: Severity
    explanation: str = Field(description="Plain-English description of the issue")
    exploit_scenario: str = Field(description="How this could be exploited")
    fix_suggestion: str = Field(description="Concrete remediation guidance")
    references: list[str] = Field(
        default_factory=list, description="OWASP/CWE doc ids used as grounding"
    )
