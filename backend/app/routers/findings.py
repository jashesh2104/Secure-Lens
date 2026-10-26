"""Findings endpoints: list and read normalized findings."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.security import require_auth
from app.database import get_db
from app.models.finding import Finding, FindingStatus
from app.schemas.finding import FindingRead
from app.services import verified_fix
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
def triage(finding_id: int, db: Session = Depends(get_db),
           _user: str = Depends(require_auth)) -> Finding:
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
    except RuntimeError as exc:  # LLM not configured (no key/endpoint)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - provider unreachable / rate-limited
        logger.warning("triage LLM call failed",
                       extra={"event": "triage_llm_error", "finding_id": finding_id,
                              "error": str(exc)})
        raise HTTPException(
            status_code=502,
            detail=f"LLM request failed ({type(exc).__name__}). Check LLM_PROVIDER "
                   f"credentials/connectivity: {str(exc)[:200]}",
        ) from exc
    finding.triage_result = result.model_dump()
    finding.status = FindingStatus.TRIAGED
    db.commit()
    db.refresh(finding)
    logger.info(
        "triage complete",
        extra={"event": "triage_complete", "finding_id": finding_id},
    )
    return finding


@router.post("/{finding_id}/fix", response_model=FindingRead)
def fix(finding_id: int, db: Session = Depends(get_db),
        _user: str = Depends(require_auth)) -> Finding:
    """Generate a fix, verify it in a sandbox, and persist the outcome.

    The verified-fix pipeline needs the repo on disk, so we resolve the scan's
    repo path. ``verified_fix`` on the response is only ``True`` when an
    independent recheck confirmed the vulnerability is gone.
    """
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    repo_path = (
        finding.scan.repo.url_or_path
        if finding.scan and finding.scan.repo else None
    )
    if not repo_path:
        raise HTTPException(status_code=409,
                            detail="Finding has no associated repo path to patch.")
    logger.info("fix started",
                extra={"event": "fix_start", "finding_id": finding_id})
    try:
        result = verified_fix.propose_and_verify_fix(finding, repo_path)
    except RuntimeError as exc:  # LLM not configured (no key/endpoint)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - provider unreachable / rate-limited
        logger.warning("fix LLM call failed",
                       extra={"event": "fix_llm_error", "finding_id": finding_id,
                              "error": str(exc)})
        raise HTTPException(
            status_code=502,
            detail=f"LLM request failed ({type(exc).__name__}). Check LLM_PROVIDER "
                   f"credentials/connectivity: {str(exc)[:200]}",
        ) from exc
    finding.verified_fix = result.model_dump()
    db.commit()
    db.refresh(finding)
    logger.info("fix complete",
                extra={"event": "fix_complete", "finding_id": finding_id,
                       "verified": result.verified})
    return finding
