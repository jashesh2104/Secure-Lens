"""SonarQube integration.

Two responsibilities:
1. Trigger an analysis by invoking the `sonar-scanner` CLI as a subprocess.
2. Fetch the resulting issues from the SonarQube Web API.

We deliberately read results from /api/issues/search rather than parsing
scanner stdout: the CLI only uploads code to the server, and the server is the
source of truth for findings. CLI output format is not a stable contract.

Verify against your SonarQube version: tested args target SonarQube 10.x+,
where the auth flag is `-Dsonar.token`. Older 9.x used `-Dsonar.login`.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import requests

from app.config import get_settings

settings = get_settings()

# SonarQube caps page size at 500 for issues/search.
_PAGE_SIZE = 500
# Avoid pulling unbounded result sets; SonarQube also caps total at 10k.
_MAX_PAGES = 20


def _work_dir(project_key: str) -> Path:
    """Per-project scanner working directory in a space-free temp location.

    The scanner writes ``report-task.txt`` here (which carries the CE task id we
    poll). The repo path can contain a space ("OneDrive - Philips") that breaks
    the scanner's default working dir, so we redirect it under %TEMP%. Keying it
    by project avoids reading a stale report-task.txt from a previous scan.
    """
    return Path(tempfile.gettempdir()) / "securelens_sonar" / project_key

# Compute Engine polling: analysis is processed asynchronously server-side, so
# we must wait for the background task to finish before reading issues.
_CE_POLL_INTERVAL_S = 3
_CE_MAX_ATTEMPTS = 10
# SUCCESS/FAILED are terminal states for the CE task; keep polling otherwise.
_CE_TERMINAL_STATES = {"SUCCESS", "FAILED"}
# When report-task.txt is absent we can't identify the CE task, so we wait a
# fixed interval for the server to finish and optimistically assume success.
_CE_FALLBACK_SLEEP_S = 30


def run_scanner(repo_path: str, project_key: str, timeout_s: int = 1800) -> None:
    """Run sonar-scanner against a local repo. Raises on non-zero exit.

    The scanner only submits the analysis; results are read afterwards via the
    Web API. `timeout_s` defaults to 30 min for large repos.
    """
    scanner = shutil.which("sonar-scanner") or "sonar-scanner"
    work = _work_dir(project_key)
    work.mkdir(parents=True, exist_ok=True)
    # Use an absolute base dir with sources=".": a relative sonar.sources like
    # "../sample_vuln" resolves outside sonar.projectBaseDir and the scanner
    # then analyzes ZERO files. Anchoring projectBaseDir to the absolute repo
    # and scanning "." reliably picks up the source tree.
    abs_repo = str(Path(repo_path).resolve())
    cmd = [
        scanner,
        f"-Dsonar.projectKey={project_key}",
        "-Dsonar.sources=.",
        f"-Dsonar.projectBaseDir={abs_repo}",
        # Analyze what the user pointed us at even if the host repo's .gitignore
        # excludes it (SonarQube skips SCM-ignored files by default). Target
        # repos are explicitly chosen, so we scan them regardless of git status.
        "-Dsonar.scm.exclusions.disabled=true",
        f"-Dsonar.host.url={settings.sonarqube_host}",
        f"-Dsonar.token={settings.sonarqube_token}",
        # Redirect scanner temp/work files out of the repo: the repo path may
        # contain a space ("OneDrive - Philips") which breaks the scanner's
        # root temp dir creation. Point at a space-free, per-project path so
        # report-task.txt is found reliably and never stale.
        f"-Dsonar.working.directory={work}",
        f"-Dsonar.userHome={Path(tempfile.gettempdir()) / 'securelens_sonarhome'}",
    ]
    result = subprocess.run(
        cmd, cwd=abs_repo, capture_output=True, text=True, timeout=timeout_s,
    )
    if result.returncode != 0:
        # sonar-scanner logs the real reason (auth, project, config) to
        # stdout/stderr; surface both so callers can diagnose the failure.
        raise subprocess.CalledProcessError(
            result.returncode, cmd,
            output=result.stdout,
            stderr=result.stderr,
        )


def _read_ce_task_id(project_key: str) -> str | None:
    """Return the CE task ID from the scanner's report-task.txt, or None.

    The scanner writes report-task.txt into ``sonar.working.directory`` (which
    we redirect via :func:`_work_dir`), not the repo. It contains a `ceTaskId=`
    line identifying the background task, letting us poll /api/ce/task (Browse
    permission) instead of /api/ce/activity (admin only).
    """
    report = _work_dir(project_key) / "report-task.txt"
    if not report.exists():
        return None
    for line in report.read_text(encoding="utf-8").splitlines():
        if line.startswith("ceTaskId="):
            return line.split("=", 1)[1].strip()
    return None


def wait_for_ce_task(project_key: str) -> str:
    """Block until SonarQube's Compute Engine finishes analyzing this project.

    The scanner only *uploads* a report; the server processes it asynchronously
    in a background Compute Engine (CE) task. Reading issues before that task
    completes returns stale/empty results, so we wait for it to finish.

    We read the CE task ID from the scanner's report-task.txt (see _work_dir)
    and poll /api/ce/task?id=<ceTaskId>, which needs only Browse permission.

    If report-task.txt is missing, or the task can't be polled (404 — e.g. a
    stale id or a permission-scoped token), we fall back to a fixed wait and
    optimistically assume success rather than failing the whole SonarQube step.

    Polls every 3s, up to 10 attempts (~30s), then raises TimeoutError.
    Returns the terminal status ("SUCCESS" or "FAILED").
    """
    ce_task_id = _read_ce_task_id(project_key)
    if ce_task_id is None:
        time.sleep(_CE_FALLBACK_SLEEP_S)
        return "SUCCESS"

    for _ in range(_CE_MAX_ATTEMPTS):
        resp = requests.get(
            f"{settings.sonarqube_host}/api/ce/task",
            params={"id": ce_task_id},
            auth=(settings.sonarqube_token, ""),
            timeout=30,
        )
        # A 404/403 here shouldn't sink the scan: the analysis was accepted, we
        # just can't track it. Wait a bit and let fetch_issues/hotspots try.
        if resp.status_code in (403, 404):
            time.sleep(_CE_FALLBACK_SLEEP_S)
            return "SUCCESS"
        resp.raise_for_status()
        status = resp.json().get("task", {}).get("status")
        if status in _CE_TERMINAL_STATES:
            return status
        time.sleep(_CE_POLL_INTERVAL_S)
    raise TimeoutError(
        f"SonarQube CE task '{ce_task_id}' for '{project_key}' did not finish "
        f"within {_CE_MAX_ATTEMPTS * _CE_POLL_INTERVAL_S}s"
    )


def fetch_issues(project_key: str) -> list[dict]:
    """Fetch all open issues for a project via /api/issues/search.

    Paginates because the API returns at most 500 per page. Returns the raw
    issue dicts; normalization happens in normalizer.py.
    """
    issues: list[dict] = []
    for page in range(1, _MAX_PAGES + 1):
        resp = requests.get(
            f"{settings.sonarqube_host}/api/issues/search",
            params={"componentKeys": project_key, "ps": _PAGE_SIZE, "p": page},
            auth=(settings.sonarqube_token, ""),
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("issues", [])
        issues.extend(batch)
        if page * _PAGE_SIZE >= data.get("total", 0):
            break
    return issues


def fetch_hotspots(project_key: str) -> list[dict]:
    """Fetch Security Hotspots for a project via /api/hotspots/search.

    Hotspots are a separate class from issues (returned by a different endpoint)
    and are where many high-value Python SAST findings land — os.system, weak
    crypto, hardcoded credentials. Requires Browse permission on the project; if
    the token lacks it the server returns 403, which we surface to the caller.
    Paginates because the API caps results per page.
    """
    hotspots: list[dict] = []
    for page in range(1, _MAX_PAGES + 1):
        resp = requests.get(
            f"{settings.sonarqube_host}/api/hotspots/search",
            params={"projectKey": project_key, "ps": _PAGE_SIZE, "p": page},
            auth=(settings.sonarqube_token, ""),
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("hotspots", [])
        hotspots.extend(batch)
        total = (data.get("paging") or {}).get("total", 0)
        if page * _PAGE_SIZE >= total:
            break
    return hotspots


def get_server_version() -> str:
    """Return the SonarQube server version for reproducibility records."""
    resp = requests.get(
        f"{settings.sonarqube_host}/api/server/version",
        auth=(settings.sonarqube_token, ""),
        timeout=10,
    )
    resp.raise_for_status()
    return resp.text.strip()
