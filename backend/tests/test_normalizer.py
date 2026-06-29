"""Tests for the normalizer and severity mapping (pure logic, no I/O)."""

from app.models.finding import Severity, SourceTool
from app.services import normalizer


def test_sonar_blocker_maps_critical():
    out = normalizer.normalize([{"rule": "S1", "severity": "BLOCKER",
                                 "component": "k:src/a.py", "line": 3,
                                 "message": "x"}], [])
    assert out[0].source_tool == SourceTool.SONARQUBE
    assert out[0].normalized_severity == Severity.CRITICAL
    assert out[0].file_path == "src/a.py"


def test_sonar_minor_maps_low():
    out = normalizer.normalize([{"rule": "S2", "severity": "MINOR",
                                 "component": "k:a.py", "message": "m"}], [])
    assert out[0].normalized_severity == Severity.LOW


def test_gitleaks_maps_high():
    out = normalizer.normalize([], [{"RuleID": "aws", "File": ".env",
                                     "StartLine": 1, "Description": "key"}])
    assert out[0].source_tool == SourceTool.GITLEAKS
    assert out[0].normalized_severity == Severity.HIGH
