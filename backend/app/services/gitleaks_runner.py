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
import re
import shutil
import subprocess
import tempfile
import uuid

# Exit codes per gitleaks docs: 0 = clean, 1 = leaks found.
_LEAKS_FOUND = 1

# Vendored/build/VCS trees that are not first-party source. They contain
# thousands of files (and, in .git, packed objects) that both blow the timeout
# and produce noise, so we exclude them from every scan via a config allowlist.
_VENDOR_DIRS = (
    ".venv", "venv", "env", "node_modules", "__pycache__", ".git", "chroma",
    "dist", "build", "site-packages", ".mypy_cache", ".pytest_cache", ".tox",
    ".idea", ".vscode",
)


def _default_config(tmp_dir: pathlib.Path) -> pathlib.Path:
    """Write a gitleaks config that keeps built-in rules but skips vendored dirs.

    ``[extend] useDefault = true`` preserves gitleaks' bundled secret rules; the
    ``[allowlist] paths`` regexes drop findings whose file lives under a
    vendored/build directory so large target repos don't time out.
    """
    lines = ['title = "securelens"', "", "[extend]", "useDefault = true", "",
             "[allowlist]", "paths = ["]
    lines += [f"  '''(^|/){re.escape(d)}/.*''',"  for d in _VENDOR_DIRS]
    lines.append("]")
    cfg = tmp_dir / "gitleaks-default.toml"
    cfg.write_text("\n".join(lines), encoding="utf-8")
    return cfg



def _scan_dir(binary: str, mode: str, target: str, config_path: pathlib.Path,
              timeout_s: int) -> list[dict]:
    """Run gitleaks against a single directory and return parsed findings."""
    # Use a full-length UUID filename instead of tempfile.mkstemp(): on Windows
    # mkstemp can hand back an 8.3 short path (e.g. 320321~1) that gitleaks
    # cannot resolve, so it never finds the report file.
    report_path = pathlib.Path(tempfile.gettempdir()) / f"gitleaks_{uuid.uuid4().hex}.json"
    try:
        cmd = [
            binary, mode, target,
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


def run_gitleaks(repo_path: str, scan_git_history: bool = False,
                 timeout_s: int = 120) -> list[dict]:
    """Scan a target repo path and return parsed findings (empty list if clean).

    Scans the whole ``repo_path`` so it works on any repository layout, not just
    SecureLens's own. Vendored/build trees are excluded via a gitleaks config
    allowlist to keep the scan fast: a user-supplied ``.gitleaks.toml`` at the
    repo root wins if present, otherwise a generated default config that keeps
    the built-in rules but skips the directories in ``_VENDOR_DIRS``. Exit code
    1 means leaks were found and is treated as success; any other non-zero code
    is a real failure.
    """
    binary = shutil.which("gitleaks") or "gitleaks"
    mode = "git" if scan_git_history else "dir"
    repo_root = pathlib.Path(repo_path)
    user_config = repo_root / ".gitleaks.toml"

    with tempfile.TemporaryDirectory() as tmp:
        config_path = (
            user_config if user_config.is_file()
            else _default_config(pathlib.Path(tmp))
        )
        return _scan_dir(binary, mode, str(repo_root), config_path, timeout_s)



def get_version() -> str:
    """Return gitleaks version string for reproducibility records."""
    binary = shutil.which("gitleaks") or "gitleaks"
    result = subprocess.run(
        [binary, "version"], capture_output=True, text=True, timeout=10
    )
    return result.stdout.strip()
