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
import time

import requests

from app.config import get_settings

settings = get_settings()

# SonarQube caps page size at 500 for issues/search.
_PAGE_SIZE = 500
# Avoid pulling unbounded result sets; SonarQube also caps total at 10k.
_MAX_PAGES = 20

# Compute Engine polling: analysis is processed asynchronously server-side, so
# we must wait for the background task to finish before reading issues.
_CE_POLL_INTERVAL_S = 3
_CE_MAX_ATTEMPTS = 10
# SUCCESS/FAILED are terminal states for the CE task; keep polling otherwise.
_CE_TERMINAL_STATES = {"SUCCESS", "FAILED"}


def run_scanner(repo_path: str, project_key: str, timeout_s: int = 1800) -> None:
    """Run sonar-scanner against a local repo. Raises on non-zero exit.

    The scanner only submits the analysis; results are read afterwards via the
    Web API. `timeout_s` defaults to 30 min for large repos.
    """
    scanner = shutil.which("sonar-scanner") or "sonar-scanner"
    cmd = [
        scanner,
        f"-Dsonar.projectKey={project_key}",
        f"-Dsonar.sources={repo_path}",
        f"-Dsonar.host.url={settings.sonarqube_host}",
        f"-Dsonar.token={settings.sonarqube_token}",
    ]
    result = subprocess.run(
        cmd, cwd=repo_path, capture_output=True, text=True, timeout=timeout_s,
    )
    if result.returncode != 0:
        # sonar-scanner logs the real reason (auth, project, config) to
        # stdout/stderr; surface both so callers can diagnose the failure.
        raise subprocess.CalledProcessError(
            result.returncode, cmd,
            output=result.stdout,
            stderr=result.stderr,
        )


def wait_for_ce_task(project_key: str) -> str:
    """Block until SonarQube's Compute Engine finishes analyzing this project.

    The scanner only *uploads* a report; the server processes it asynchronously
    in a background Compute Engine (CE) task. Reading issues before that task
    completes returns stale/empty results, so we poll the CE activity feed for
    the project's most recent task until it reaches a terminal state.

    Polls every 3s, up to 10 attempts (~30s), then raises TimeoutError.
    Returns the terminal status ("SUCCESS" or "FAILED").
    """
    auth = (settings.sonarqube_token, "") if settings.sonarqube_token else None
    for _ in range(_CE_MAX_ATTEMPTS):
        resp = requests.get(
            f"{settings.sonarqube_host}/api/ce/activity",
            params={"component": project_key, "ps": 1},
            auth=auth,
            timeout=30,
        )
        resp.raise_for_status()
        tasks = resp.json().get("tasks", [])
        if tasks and tasks[0].get("status") in _CE_TERMINAL_STATES:
            return tasks[0]["status"]
        time.sleep(_CE_POLL_INTERVAL_S)
    raise TimeoutError(
        f"SonarQube CE task for '{project_key}' did not finish within "
        f"{_CE_MAX_ATTEMPTS * _CE_POLL_INTERVAL_S}s"
    )


def fetch_issues(project_key: str) -> list[dict]:
    """Fetch all open issues for a project via /api/issues/search.

    Paginates because the API returns at most 500 per page. Returns the raw
    issue dicts; normalization happens in normalizer.py.
    """
    issues: list[dict] = []
    auth = (settings.sonarqube_token, "") if settings.sonarqube_token else None
    for page in range(1, _MAX_PAGES + 1):
        resp = requests.get(
            f"{settings.sonarqube_host}/api/issues/search",
            params={"componentKeys": project_key, "ps": _PAGE_SIZE, "p": page},
            auth=auth,
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("issues", [])
        issues.extend(batch)
        if page * _PAGE_SIZE >= data.get("total", 0):
            break
    return issues


def get_server_version() -> str:
    """Return the SonarQube server version for reproducibility records."""
    resp = requests.get(f"{settings.sonarqube_host}/api/server/version", timeout=10)
    resp.raise_for_status()
    return resp.text.strip()
