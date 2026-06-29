# SecureLens — backend

AI-augmented DevSecOps triage platform. Phase 1 is a FastAPI skeleton with a
`/health` endpoint, config, and DB engine wiring.

## Local setup (Windows, no Docker)

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env   # then fill in values
uvicorn app.main:app --reload --port 8000
```

Verify: open http://localhost:8000/health — expect `{"status":"ok",...}`.
API docs at http://localhost:8000/docs.
