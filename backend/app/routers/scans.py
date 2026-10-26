"""Scan endpoints: start a scan and read its result.

The scan runs synchronously here (no Celery yet, by design): the request
blocks while SonarQube + Gitleaks run, then findings are normalized, persisted,
and returned. Each scanner is wrapped independently so one missing tool doesn't
sink the whole scan; failures are recorded in tool_versions.
"""

import logging
import re
import threading
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.rate_limit import limiter
from app.core.security import require_auth
from app.database import SessionLocal, create_engine, get_db
from app.models.finding import Finding, FindingStatus
from app.models.repo import Repo
from app.models.scan import Scan, ScanStatus
from app.schemas.scan import ScanCreate, ScanDetail, ScanRead
from app.services import (
    gitleaks_runner,
    normalizer,
    priority as priority_service,
    reachability as reachability_service,
    sonarqube_runner,
)
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

    scan = Scan(repo_id=repo.id, status=ScanStatus.PENDING,
                started_at=datetime.now(timezone.utc))
    db.add(scan)
    db.commit()
    db.refresh(scan)
    logger.info(
        "scan queued",
        extra={"event": "scan_queued", "scan_id": scan.id, "repo": payload.name},
    )

    # SonarQube analysis takes minutes; run it off-request so the HTTP call
    # returns immediately and the client polls GET /scan/{id} for progress.
    threading.Thread(
        target=run_scan_background,
        args=(scan.id, payload.url_or_path, payload.name,
              get_settings().database_url),
        daemon=True,
    ).start()

    return scan


def _annotate_reachability(findings: list[Finding], repo_path: str) -> None:
    """Attach reachability + priority to each finding via static analysis.

    Best-effort: a failure here must never sink the scan, so we log and leave
    the annotations null rather than raising.
    """
    if not findings:
        return
    try:
        graph = reachability_service.analyze_repo(repo_path)
    except Exception:  # noqa: BLE001 - never let analysis crash a scan
        logger.exception("reachability analysis failed", extra={"repo": repo_path})
        return
    for finding in findings:
        try:
            reach = reachability_service.reachability_for(
                graph, finding.file_path, finding.line_number
            )
            prio = priority_service.compute_priority(
                finding.normalized_severity, reach, finding.source_tool
            )
            finding.reachability = reach.model_dump()
            finding.priority = prio.model_dump()
        except Exception:  # noqa: BLE001 - annotate best-effort, per finding
            logger.warning(
                "reachability annotation failed for finding",
                extra={"file": finding.file_path, "line": finding.line_number},
            )


def run_scan_background(
    scan_id: int, repo_path: str, repo_name: str, db_url: str
) -> None:
    """Run the scanners for a queued scan in a background thread.

    The request's SQLAlchemy session can't cross the thread boundary, so we
    build a private engine + session from db_url and own its whole lifecycle
    here. Status moves pending -> running -> completed/failed as we go.
    """
    connect_args = (
        {"check_same_thread": False, "timeout": 30}
        if db_url.startswith("sqlite") else {}
    )
    engine = create_engine(db_url, connect_args=connect_args, pool_pre_ping=True)
    db = SessionLocal(bind=engine)
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            logger.error("scan vanished before background run",
                         extra={"scan_id": scan_id})
            return

        scan.status = ScanStatus.RUNNING
        db.commit()
        logger.info(
            "scan started",
            extra={"event": "scan_start", "scan_id": scan_id, "repo": repo_name},
        )

        tool_versions: dict[str, str] = {}
        sonar_issues: list[dict] = []
        sonar_hotspots: list[dict] = []
        gitleaks_findings: list[dict] = []

        try:
            key = _project_key(repo_name)
            sonarqube_runner.run_scanner(repo_path, key)
            sonarqube_runner.wait_for_ce_task(key)  # wait for async CE processing
            sonar_issues = sonarqube_runner.fetch_issues(key)
            tool_versions["sonarqube"] = sonarqube_runner.get_server_version()
            # Hotspots are a separate endpoint and need Browse permission; a
            # failure here (e.g. 403 for an analysis-only token) must not
            # discard the issues we already fetched, so isolate it.
            try:
                sonar_hotspots = sonarqube_runner.fetch_hotspots(key)
            except Exception as exc:  # noqa: BLE001
                tool_versions["sonarqube_hotspots_error"] = str(exc)[:500]
        except Exception as exc:  # noqa: BLE001 - record, don't crash the scan
            # Include scanner stdout/stderr when present (CalledProcessError) so
            # the stored error explains *why* the scan failed, not just the code.
            stderr = getattr(exc, "stderr", "") or ""
            stdout = getattr(exc, "stdout", "") or ""
            tool_versions["sonarqube_error"] = (
                f"{exc} | stderr: {stderr} | stdout: {stdout}"
            )[:2000]

        try:
            gitleaks_findings = gitleaks_runner.run_gitleaks(repo_path)
            tool_versions["gitleaks"] = gitleaks_runner.get_version()
        except Exception as exc:  # noqa: BLE001
            tool_versions["gitleaks_error"] = str(exc)[:500]

        findings_count = 0
        new_findings: list[Finding] = []
        for fc in normalizer.normalize(sonar_issues, gitleaks_findings, repo_path,
                                       sonar_hotspots):
            finding = Finding(scan_id=scan_id, **fc.model_dump())
            db.add(finding)
            new_findings.append(finding)
            findings_count += 1

        # Codebase-aware reachability + priority. Deterministic and API-key-free,
        # so it always runs at scan time — this is what ranks the queue by real,
        # repo-specific risk instead of raw scanner severity.
        _annotate_reachability(new_findings, repo_path)

        both_failed = (
            "sonarqube" not in tool_versions and "gitleaks" not in tool_versions
        )
        scan.status = ScanStatus.FAILED if both_failed else ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.tool_versions = tool_versions
        db.commit()
        logger.info(
            "scan complete",
            extra={
                "event": "scan_complete",
                "scan_id": scan_id,
                "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
                "findings": findings_count,
            },
        )
    except Exception:  # noqa: BLE001 - never let the thread die silently
        logger.exception("scan background run failed", extra={"scan_id": scan_id})
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan is not None:
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()
        engine.dispose()


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
def triage_scan(scan_id: int, db: Session = Depends(get_db),
                _user: str = Depends(require_auth)) -> Scan:
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
        time.sleep(2)  # throttle Groq calls to stay under the rate limit during batch triage
        try:
            finding.triage_result = triage_finding(finding).model_dump()
            finding.status = FindingStatus.TRIAGED
            triaged += 1
        except Exception as exc:  # noqa: BLE001 - keep going; report partial result
            logger.warning(
                "triage failed for finding; skipping",
                extra={"event": "triage_finding_error", "scan_id": scan_id,
                       "finding_id": finding.id, "error": str(exc)},
            )
            finding.triage_result = None
            continue
    db.commit()
    db.refresh(scan)
    logger.info(
        "triage complete",
        extra={"event": "triage_complete", "scan_id": scan_id, "triaged": triaged},
    )
    return scan
