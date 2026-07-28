"""Findings endpoints: list and read normalized findings."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.security import require_auth
from app.database import get_db
from app.models.finding import Finding, FindingStatus
from app.schemas.finding import FindingRead
from app.services.triage_agent import triage_finding

router = APIRouter(prefix="/findings", tags=["findings"])
logger = logging.getLogger("securelens.findings")


@router.get("", response_model=list[FindingRead])
def list_findings(
    scan_id: int | None = Query(default=None, description="Filter by scan"),
    severity: str | None = Query(default=None, description="Filter by raw severity"),
    source_tool: str | None = Query(default=None, description="Filter by source tool"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1),
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
) -> list[Finding]:
    query = db.query(Finding)
    if scan_id is not None:
        query = query.filter(Finding.scan_id == scan_id)
    if severity is not None:
        query = query.filter(Finding.severity == severity)
    if source_tool is not None:
        query = query.filter(Finding.source_tool == source_tool)
    return query.offset(skip).limit(limit).all()


@router.get("/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: int, db: Session = Depends(get_db)) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.post("/{finding_id}/triage", response_model=FindingRead)
def triage(finding_id: int, db: Session = Depends(get_db)) -> Finding:
    """Run RAG triage on a finding and persist the result."""
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    logger.info(
        "triage started",
        extra={"event": "triage_start", "finding_id": finding_id},
    )
    try:
        result = triage_finding(finding)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finding.triage_result = result.model_dump()
    finding.status = FindingStatus.TRIAGED
    db.commit()
    db.refresh(finding)
    logger.info(
        "triage complete",
        extra={"event": "triage_complete", "finding_id": finding_id},
    )
    return finding
