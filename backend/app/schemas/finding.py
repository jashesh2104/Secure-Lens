"""Pydantic schemas for the unified Finding.

These define the API contract for findings. `from_attributes=True` lets us
return SQLAlchemy ORM objects directly from FastAPI and have them serialized,
so the model layer and API layer stay decoupled.
"""

from pydantic import BaseModel, ConfigDict

from app.models.finding import FindingStatus, Severity, SourceTool


class FindingBase(BaseModel):
    source_tool: SourceTool
    severity: str  # raw severity from the tool
    normalized_severity: Severity
    rule_id: str
    file_path: str
    line_number: int | None = None
    message: str


class FindingCreate(FindingBase):
    """Shape the normalizer produces before findings are persisted."""


class FindingRead(FindingBase):
    id: int
    scan_id: int
    status: FindingStatus
    triage_result: dict | None = None

    model_config = ConfigDict(from_attributes=True)
