"""Scan endpoints: start a scan and read its result.

The scan runs synchronously here (no Celery yet, by design): the request
blocks while SonarQube + Gitleaks run, then findings are normalized, persisted,
and returned. Each scanner is wrapped independently so one missing tool doesn't
sink the whole scan; failures are recorded in tool_versions.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import Finding, FindingStatus
from app.models.repo import Repo
from app.models.scan import Scan, ScanStatus
from app.schemas.scan import ScanCreate, ScanDetail
from app.services import gitleaks_runner, normalizer, sonarqube_runner
from app.services.triage_agent import triage_finding

router = APIRouter(prefix="/scan", tags=["scans"])


def _project_key(name: str) -> str:
    """SonarQube project keys allow letters, digits, -, _, ., :; normalize."""
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", name)


@router.post("", response_model=ScanDetail, status_code=201)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)) -> Scan:
    repo = Repo(name=payload.name, url_or_path=payload.url_or_path)
    db.add(repo)
    db.flush()  # assign repo.id without ending the transaction

    scan = Scan(repo_id=repo.id, status=ScanStatus.RUNNING,
                started_at=datetime.now(timezone.utc))
    db.add(scan)
    db.flush()

    tool_versions: dict[str, str] = {}
    sonar_issues: list[dict] = []
    gitleaks_findings: list[dict] = []

    try:
        sonarqube_runner.run_scanner(payload.url_or_path, _project_key(payload.name))
        sonar_issues = sonarqube_runner.fetch_issues(_project_key(payload.name))
        tool_versions["sonarqube"] = sonarqube_runner.get_server_version()
    except Exception as exc:  # noqa: BLE001 - record, don't crash the scan
        tool_versions["sonarqube_error"] = str(exc)[:500]

    try:
        gitleaks_findings = gitleaks_runner.run_gitleaks(payload.url_or_path)
        tool_versions["gitleaks"] = gitleaks_runner.get_version()
    except Exception as exc:  # noqa: BLE001
        tool_versions["gitleaks_error"] = str(exc)[:500]

    for fc in normalizer.normalize(sonar_issues, gitleaks_findings):
        db.add(Finding(scan_id=scan.id, **fc.model_dump()))

    both_failed = "sonarqube" not in tool_versions and "gitleaks" not in tool_versions
    scan.status = ScanStatus.FAILED if both_failed else ScanStatus.COMPLETED
    scan.completed_at = datetime.now(timezone.utc)
    scan.tool_versions = tool_versions
    db.commit()
    db.refresh(scan)
    return scan


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
    for finding in scan.findings:
        if finding.status == FindingStatus.TRIAGED:
            continue
        try:
            finding.triage_result = triage_finding(finding).model_dump()
            finding.status = FindingStatus.TRIAGED
        except Exception:  # noqa: BLE001 - keep going; report partial result
            continue
    db.commit()
    db.refresh(scan)
    return scan
