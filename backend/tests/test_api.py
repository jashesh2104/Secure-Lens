"""API smoke tests with overridden in-memory DB. No external services needed."""


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_findings_empty(client):
    assert client.get("/findings").json() == []


def test_scan_not_found(client):
    assert client.get("/scan/999").status_code == 404
