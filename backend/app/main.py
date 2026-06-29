"""FastAPI application entrypoint.

Run locally with:
    uvicorn app.main:app --reload --port 8000

Phase 1 ships only a wiring skeleton plus a /health endpoint so we can confirm
the app boots, settings load, and the server responds before adding models,
routers, and the RAG layer.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routers import findings, scans

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description="AI-augmented DevSecOps triage platform",
    version="0.1.0",
)

# Allow the local Vite dev server to call the API directly. In production the
# SPA is served by the same nginx that proxies /api, so this is dev-only.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)
app.include_router(findings.router)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    """Liveness probe. Returns 200 with basic app metadata.

    Kept dependency-free on purpose so it works before the DB/scanners exist
    and stays usable as a CI/CD readiness check later.
    """
    return {"status": "ok", "app": settings.app_name, "version": "0.1.0"}
