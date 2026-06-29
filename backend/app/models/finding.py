"""Finding model: a single normalized issue from any scanner.

This is the unified schema both SonarQube and Gitleaks output gets mapped into,
so the rest of the system (dashboard, RAG triage, PR gate) reads one shape
instead of two tool-specific ones. `severity` is our normalized scale; raw tool
severities are mapped in normalizer.py. `triage_result` stays empty until the
Phase 2 RAG pipeline fills it, which is why it's nullable.
"""

import enum

from sqlalchemy import Enum, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class SourceTool(str, enum.Enum):
    SONARQUBE = "sonarqube"
    GITLEAKS = "gitleaks"


class Severity(str, enum.Enum):
    """Normalized severity scale shared across all tools."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(str, enum.Enum):
    NEW = "new"
    TRIAGED = "triaged"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    source_tool: Mapped[SourceTool] = mapped_column(Enum(SourceTool), nullable=False)
    # Raw severity string straight from the tool, kept for traceability.
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    # Our normalized scale, derived in normalizer.py.
    normalized_severity: Mapped[Severity] = mapped_column(
        Enum(Severity), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus), default=FindingStatus.NEW, nullable=False
    )
    # Filled by the RAG triage agent in Phase 2; nullable until then.
    triage_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")  # noqa: F821
