"""API smoke tests with overridden in-memory DB. No external services needed."""


def _auth_header(client):
    """Register a user and return a bearer header for protected routes."""
    r = client.post("/auth/register", json={"username": "tester", "password": "password123"})
    assert r.status_code == 201
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_findings_requires_auth(client):
    assert client.get("/findings").status_code == 401


def test_findings_empty(client):
    assert client.get("/findings", headers=_auth_header(client)).json() == []


def test_scan_not_found(client):
    assert client.get("/scan/999").status_code == 404


def test_list_scans_returns_list(client):
    r = client.get("/scans")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_list_findings_with_scan_id_filter(client):
    r = client.get("/findings", params={"scan_id": 1}, headers=_auth_header(client))
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_list_findings_with_severity_filter(client):
    r = client.get("/findings", params={"severity": "MAJOR"}, headers=_auth_header(client))
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_list_findings_without_auth_returns_401(client):
    assert client.get("/findings").status_code == 401
