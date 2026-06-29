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

import requests

from app.config import get_settings

settings = get_settings()

# SonarQube caps page size at 500 for issues/search.
_PAGE_SIZE = 500
# Avoid pulling unbounded result sets; SonarQube also caps total at 10k.
_MAX_PAGES = 20


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
    subprocess.run(
        cmd, cwd=repo_path, check=True, capture_output=True, text=True,
        timeout=timeout_s,
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
