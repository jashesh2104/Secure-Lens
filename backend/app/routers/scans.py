"""Scan endpoints: start a scan and read its result.

The scan runs synchronously here (no Celery yet, by design): the request
blocks while SonarQube + Gitleaks run, then findings are normalized, persisted,
and returned. Each scanner is wrapped independently so one missing tool doesn't
sink the whole scan; failures are recorded in tool_versions.
"""

import logging
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.rate_limit import limiter
from app.core.security import require_auth
from app.database import get_db
from app.models.finding import Finding, FindingStatus
from app.models.repo import Repo
from app.models.scan import Scan, ScanStatus
from app.schemas.scan import ScanCreate, ScanDetail, ScanRead
from app.services import gitleaks_runner, normalizer, sonarqube_runner
from app.services.triage_agent import triage_finding

router = APIRouter(prefix="/scan", tags=["scans"])
logger = logging.getLogger("securelens.scans")


def _project_key(name: str) -> str:
    """Derive a SonarQube-safe project key from a scan name.

    Some SonarQube versions reject keys containing hyphens, so we fold hyphens
    and spaces to underscores and strip anything that isn't alphanumeric or an
    underscore.
    """
    key = name.lower().replace("-", "_").replace(" ", "_")
    return re.sub(r"[^a-z0-9_]", "", key)


@router.post("", response_model=ScanDetail, status_code=201)
@limiter.limit("5/minute")
def create_scan(
    request: Request,
    payload: ScanCreate,
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
) -> Scan:
    repo = Repo(name=payload.name, url_or_path=payload.url_or_path)
    db.add(repo)
    db.flush()  # assign repo.id without ending the transaction

    scan = Scan(repo_id=repo.id, status=ScanStatus.RUNNING,
                started_at=datetime.now(timezone.utc))
    db.add(scan)
    db.flush()
    logger.info(
        "scan started",
        extra={"event": "scan_start", "scan_id": scan.id, "repo": payload.name},
    )

    tool_versions: dict[str, str] = {}
    sonar_issues: list[dict] = []
    gitleaks_findings: list[dict] = []

    try:
        key = _project_key(payload.name)
        sonarqube_runner.run_scanner(payload.url_or_path, key)
        sonarqube_runner.wait_for_ce_task(key)  # wait for async CE processing
        sonar_issues = sonarqube_runner.fetch_issues(key)
        tool_versions["sonarqube"] = sonarqube_runner.get_server_version()
    except Exception as exc:  # noqa: BLE001 - record, don't crash the scan
        # Include scanner stdout/stderr when present (CalledProcessError) so the
        # stored error explains *why* the scan failed, not just the exit code.
        stderr = getattr(exc, "stderr", "") or ""
        stdout = getattr(exc, "stdout", "") or ""
        tool_versions["sonarqube_error"] = (
            f"{exc} | stderr: {stderr} | stdout: {stdout}"
        )[:2000]

    try:
        gitleaks_findings = gitleaks_runner.run_gitleaks(payload.url_or_path)
        tool_versions["gitleaks"] = gitleaks_runner.get_version()
    except Exception as exc:  # noqa: BLE001
        tool_versions["gitleaks_error"] = str(exc)[:500]

    findings_count = 0
    for fc in normalizer.normalize(sonar_issues, gitleaks_findings, payload.url_or_path):
        db.add(Finding(scan_id=scan.id, **fc.model_dump()))
        findings_count += 1

    both_failed = "sonarqube" not in tool_versions and "gitleaks" not in tool_versions
    scan.status = ScanStatus.FAILED if both_failed else ScanStatus.COMPLETED
    scan.completed_at = datetime.now(timezone.utc)
    scan.tool_versions = tool_versions
    db.commit()
    db.refresh(scan)
    logger.info(
        "scan complete",
        extra={
            "event": "scan_complete",
            "scan_id": scan.id,
            "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
            "findings": findings_count,
        },
    )
    return scan


# Prefix is "/scan", so path "s" resolves to GET /scans. No auth: this is a
# read-only listing for the dashboard.
@router.get("s", response_model=list[ScanRead])
def list_scans(
    skip: int = 0,
    limit: int = 20,
    db: Session = Depends(get_db),
) -> list[Scan]:
    return (
        db.query(Scan)
        .order_by(Scan.started_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/triage", response_model=ScanDetail)
def triage_scan(scan_id: int, db: Session = Depends(get_db)) -> Scan:
    """Triage every not-yet-triaged finding in a scan. Skips on errors per
    finding so one bad call doesn't abort the batch."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    logger.info("triage started", extra={"event": "triage_start", "scan_id": scan_id})
    triaged = 0
    for finding in scan.findings:
        if finding.status == FindingStatus.TRIAGED:
            continue
        try:
            finding.triage_result = triage_finding(finding).model_dump()
            finding.status = FindingStatus.TRIAGED
            triaged += 1
        except Exception:  # noqa: BLE001 - keep going; report partial result
            continue
    db.commit()
    db.refresh(scan)
    logger.info(
        "triage complete",
        extra={"event": "triage_complete", "scan_id": scan_id, "triaged": triaged},
    )
    return scan
