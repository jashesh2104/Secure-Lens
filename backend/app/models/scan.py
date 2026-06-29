"""Scan model: one execution of the scanners against a repo.

A scan is the unit of work. It has a lifecycle (pending -> running ->
completed/failed) so the dashboard can poll status, and it records which tool
versions produced the findings — important for reproducibility and for
defending results later ("this finding came from SonarQube X, Gitleaks Y").
"""

import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ScanStatus(str, enum.Enum):
    """Lifecycle states for a scan. str-mixin keeps JSON/serialization clean."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repo_id: Mapped[int] = mapped_column(
        ForeignKey("repos.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # e.g. {"sonarqube": "10.7", "gitleaks": "8.21"}. JSON so we don't hardcode
    # tool columns; portable across SQLite and Postgres.
    tool_versions: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    repo: Mapped["Repo"] = relationship("Repo", back_populates="scans")  # noqa: F821
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
