"""Repo model: a target repository SecureLens scans.

We persist repos so each scan links back to a known target and we can show
history per repository over time, rather than treating every scan as orphaned.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Repo(Base):
    __tablename__ = "repos"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Human-friendly identifier shown in the dashboard.
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # A local filesystem path (dev) or a git URL (later) — one field keeps the
    # source generic so we don't need separate columns per scan target type.
    url_or_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    scans: Mapped[list["Scan"]] = relationship(  # noqa: F821
        "Scan", back_populates="repo", cascade="all, delete-orphan"
    )
