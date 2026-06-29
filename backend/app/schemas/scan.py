"""Pydantic schemas for Scan request/response shapes."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.scan import ScanStatus
from app.schemas.finding import FindingRead


class ScanCreate(BaseModel):
    """Request to start a scan: identify the target repo."""

    name: str
    url_or_path: str


class ScanRead(BaseModel):
    id: int
    repo_id: int
    status: ScanStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    tool_versions: dict | None = None

    model_config = ConfigDict(from_attributes=True)


class ScanDetail(ScanRead):
    """Scan plus its findings, returned from GET /scan/{id}."""

    findings: list[FindingRead] = []
