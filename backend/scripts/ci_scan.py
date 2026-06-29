"""CI entrypoint: scan the checked-out repo, comment on the PR, gate the merge.

Run by GitHub Actions. Reads GITHUB_REPOSITORY, PR_NUMBER, GITHUB_TOKEN from
env. Exits 1 if a blocking-severity finding exists so the workflow fails and
branch protection blocks merge. Does NOT call the LLM here (kept fast/free);
triage runs in the dashboard.

    .\.venv\Scripts\python.exe -m scripts.ci_scan <repo_path>
"""

from __future__ import annotations

import os
import sys

from app.models.finding import Finding
from app.services import github_pr, gitleaks_runner, normalizer, sonarqube_runner


def main() -> int:
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    project_key = os.environ.get("GITHUB_REPOSITORY", "local").replace("/", "_")

    sonar: list[dict] = []
    leaks: list[dict] = []
    try:
        sonarqube_runner.run_scanner(repo_path, project_key)
        sonar = sonarqube_runner.fetch_issues(project_key)
    except Exception as exc:  # noqa: BLE001
        print(f"sonar skipped: {exc}")
    try:
        leaks = gitleaks_runner.run_gitleaks(repo_path)
    except Exception as exc:  # noqa: BLE001
        print(f"gitleaks skipped: {exc}")

    findings = [Finding(**fc.model_dump()) for fc in normalizer.normalize(sonar, leaks)]
    print(github_pr.render_comment(findings))

    repo, pr = os.environ.get("GITHUB_REPOSITORY"), os.environ.get("PR_NUMBER")
    if repo and pr:
        github_pr.post_pr_comment(repo, int(pr), github_pr.render_comment(findings))

    return 1 if github_pr.severity_gate(findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
