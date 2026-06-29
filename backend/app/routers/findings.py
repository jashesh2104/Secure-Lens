"""Findings endpoints: list and read normalized findings."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import Finding, FindingStatus
from app.schemas.finding import FindingRead
from app.services.triage_agent import triage_finding

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingRead])
def list_findings(
    scan_id: int | None = Query(default=None, description="Filter by scan"),
    db: Session = Depends(get_db),
) -> list[Finding]:
    stmt = select(Finding)
    if scan_id is not None:
        stmt = stmt.where(Finding.scan_id == scan_id)
    return list(db.scalars(stmt).all())


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
    try:
        result = triage_finding(finding)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finding.triage_result = result.model_dump()
    finding.status = FindingStatus.TRIAGED
    db.commit()
    db.refresh(finding)
    return finding
