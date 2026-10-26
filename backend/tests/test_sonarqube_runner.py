"""Unit tests for sonarqube_runner Compute Engine polling and hotspot fetch.

The CE task is processed asynchronously server-side, so wait_for_ce_task reads
the ceTaskId from the scanner's report-task.txt (in the redirected working dir)
and polls /api/ce/task until the task reaches a terminal state. We mock
requests.get (and time.sleep) so no SonarQube server is needed.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.services import sonarqube_runner


def _point_work_dir(monkeypatch, tmp_path, ce_task_id="AXtaskid", write=True):
    """Redirect _work_dir to a temp dir and optionally seed report-task.txt."""
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(sonarqube_runner, "_work_dir", lambda pk: work)
    if write:
        (work / "report-task.txt").write_text(
            f"projectKey=proj\nceTaskId={ce_task_id}\nceTaskUrl=http://x\n",
            encoding="utf-8",
        )


def _resp(status: str, status_code: int = 200) -> MagicMock:
    """Build a fake requests Response whose CE task has the given status."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"task": {"status": status}}
    return resp


def test_wait_for_ce_task_success_first_attempt(monkeypatch, tmp_path):
    _point_work_dir(monkeypatch, tmp_path)
    with patch.object(
        sonarqube_runner.requests, "get", return_value=_resp("SUCCESS")
    ) as mock_get:
        result = sonarqube_runner.wait_for_ce_task("proj")

    assert result == "SUCCESS"
    assert mock_get.call_count == 1


def test_wait_for_ce_task_failed_first_attempt(monkeypatch, tmp_path):
    _point_work_dir(monkeypatch, tmp_path)
    with patch.object(
        sonarqube_runner.requests, "get", return_value=_resp("FAILED")
    ) as mock_get:
        result = sonarqube_runner.wait_for_ce_task("proj")

    assert result == "FAILED"
    assert mock_get.call_count == 1


def test_wait_for_ce_task_timeout_when_never_terminal(monkeypatch, tmp_path):
    _point_work_dir(monkeypatch, tmp_path)
    # Never reaches a terminal state -> should exhaust attempts and raise.
    monkeypatch.setattr(sonarqube_runner.time, "sleep", lambda *_: None)
    with patch.object(
        sonarqube_runner.requests, "get", return_value=_resp("IN_PROGRESS")
    ) as mock_get:
        with pytest.raises(TimeoutError):
            sonarqube_runner.wait_for_ce_task("proj")

    assert mock_get.call_count == sonarqube_runner._CE_MAX_ATTEMPTS


def test_wait_for_ce_task_missing_report_falls_back(monkeypatch, tmp_path):
    # No report-task.txt -> fall back to a sleep, assume SUCCESS, no HTTP call.
    _point_work_dir(monkeypatch, tmp_path, write=False)
    monkeypatch.setattr(sonarqube_runner.time, "sleep", lambda *_: None)
    with patch.object(sonarqube_runner.requests, "get") as mock_get:
        result = sonarqube_runner.wait_for_ce_task("proj")

    assert result == "SUCCESS"
    assert mock_get.call_count == 0


def test_wait_for_ce_task_tolerates_404(monkeypatch, tmp_path):
    # A 404 (stale id / permission-scoped token) must not sink the scan.
    _point_work_dir(monkeypatch, tmp_path)
    monkeypatch.setattr(sonarqube_runner.time, "sleep", lambda *_: None)
    with patch.object(
        sonarqube_runner.requests, "get", return_value=_resp("", status_code=404)
    ):
        result = sonarqube_runner.wait_for_ce_task("proj")

    assert result == "SUCCESS"


def test_fetch_hotspots_paginates_and_parses(monkeypatch):
    page = {
        "paging": {"total": 1},
        "hotspots": [{"key": "h1", "component": "proj:app.py", "line": 6,
                      "vulnerabilityProbability": "HIGH", "ruleKey": "python:S4721",
                      "message": "OS command"}],
    }
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status.return_value = None
    resp.json.return_value = page
    with patch.object(sonarqube_runner.requests, "get", return_value=resp):
        out = sonarqube_runner.fetch_hotspots("proj")

    assert len(out) == 1
    assert out[0]["ruleKey"] == "python:S4721"
