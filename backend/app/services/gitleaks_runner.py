"""Gitleaks integration: run the binary and read its JSON report.

Note: `gitleaks detect` was deprecated in v8.19.0. Current scan modes are
`dir` (scan files/folder contents) and `git` (scan commit history). We use
`dir` by default because it works on any folder, git repo or not. Gitleaks
exits 0 when no leaks are found and 1 when leaks ARE found, so a return code of
1 is success-with-findings, not an error.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import tempfile
import uuid

# Exit codes per gitleaks docs: 0 = clean, 1 = leaks found.
_LEAKS_FOUND = 1


def run_gitleaks(repo_path: str, scan_git_history: bool = False,
                 timeout_s: int = 120) -> list[dict]:
    """Scan a repo path and return parsed findings (empty list if clean).

    Writes the report to a temp file (`--report-path`) and reads it back, since
    that is the documented, stable output contract. Exit code 1 means leaks were
    found and is treated as success; any other non-zero code is a real failure.
    """
    binary = shutil.which("gitleaks") or "gitleaks"
    mode = "git" if scan_git_history else "dir"
    # Use a full-length UUID filename instead of tempfile.mkstemp(): on Windows
    # mkstemp can hand back an 8.3 short path (e.g. 320321~1) that gitleaks
    # cannot resolve, so it never finds the report file.
    report_path = pathlib.Path(tempfile.gettempdir()) / f"gitleaks_{uuid.uuid4().hex}.json"
    # Skip heavy vendored/build dirs (.venv, node_modules, chroma, .git, ...)
    # so large repos don't blow the timeout. gitleaks 8.x has no path-exclusion
    # CLI flag; the supported mechanism is a config file with [allowlist] paths.
    config_path = pathlib.Path(repo_path) / ".gitleaks.toml"
    try:
        cmd = [
            binary, mode, repo_path,
            "--report-format", "json",
            "--report-path", str(report_path),
            "--no-banner",
        ]
        if config_path.is_file():
            cmd += ["--config", str(config_path)]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s
        )
        if result.returncode not in (0, _LEAKS_FOUND):
            raise RuntimeError(
                f"gitleaks failed (exit {result.returncode}): {result.stderr}"
            )
        content = report_path.read_text(encoding="utf-8").strip()
        return json.loads(content) if content else []
    finally:
        if report_path.exists():
            report_path.unlink()


def get_version() -> str:
    """Return gitleaks version string for reproducibility records."""
    binary = shutil.which("gitleaks") or "gitleaks"
    result = subprocess.run(
        [binary, "version"], capture_output=True, text=True, timeout=10
    )
    return result.stdout.strip()
