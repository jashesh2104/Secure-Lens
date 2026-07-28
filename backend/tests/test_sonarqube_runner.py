"""Unit tests for sonarqube_runner.wait_for_ce_task Compute Engine polling.

The CE task is processed asynchronously server-side, so wait_for_ce_task polls
/api/ce/activity until the task reaches a terminal state. We mock requests.get
(and time.sleep) so no SonarQube server is needed and the timeout case is fast.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.services import sonarqube_runner


def _resp(status: str) -> MagicMock:
    """Build a fake requests Response whose CE activity has the given status."""
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"tasks": [{"status": status}]}
    return resp


def test_wait_for_ce_task_success_first_attempt():
    with patch.object(
        sonarqube_runner.requests, "get", return_value=_resp("SUCCESS")
    ) as mock_get:
        result = sonarqube_runner.wait_for_ce_task("proj")

    assert result == "SUCCESS"
    assert mock_get.call_count == 1


def test_wait_for_ce_task_failed_first_attempt():
    with patch.object(
        sonarqube_runner.requests, "get", return_value=_resp("FAILED")
    ) as mock_get:
        result = sonarqube_runner.wait_for_ce_task("proj")

    assert result == "FAILED"
    assert mock_get.call_count == 1


def test_wait_for_ce_task_timeout_when_never_terminal(monkeypatch):
    # Never reaches a terminal state -> should exhaust attempts and raise.
    monkeypatch.setattr(sonarqube_runner.time, "sleep", lambda *_: None)
    with patch.object(
        sonarqube_runner.requests, "get", return_value=_resp("IN_PROGRESS")
    ) as mock_get:
        with pytest.raises(TimeoutError):
            sonarqube_runner.wait_for_ce_task("proj")

    assert mock_get.call_count == sonarqube_runner._CE_MAX_ATTEMPTS
