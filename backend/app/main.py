"""FastAPI application entrypoint.

Run locally with:
    uvicorn app.main:app --reload --port 8000

Phase 1 ships only a wiring skeleton plus a /health endpoint so we can confirm
the app boots, settings load, and the server responds before adding models,
routers, and the RAG layer.
"""

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import get_settings
from app.core.logging_config import configure_logging, request_id_var
from app.core.rate_limit import limiter
from app.routers import auth, findings, scans

configure_logging()
logger = logging.getLogger("securelens.app")

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown hook.

    Refuse to boot with a weak JWT secret so a default or too-short value can
    never reach production, where it would let anyone forge auth tokens.
    """
    if settings.jwt_secret == "change-me-in-prod" or len(settings.jwt_secret) < 32:
        raise RuntimeError(
            "JWT_SECRET is weak: it must be changed from the default "
            "'change-me-in-prod' and be at least 32 characters long."
        )
    yield


app = FastAPI(
    title=settings.app_name,
    description="AI-augmented DevSecOps triage platform",
    version="0.1.0",
    lifespan=lifespan,
)

# Wire the shared limiter into the app so @limiter.limit(...) decorators work,
# and translate rate-limit breaches into a clean 429 response.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Allow the local Vite dev server to call the API directly. In production the
# SPA is served by the same nginx that proxies /api, so this is dev-only.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Assign each request an ID (honoring an inbound X-Request-ID) and make it
    available to loggers via a ContextVar and on request.state."""
    rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    request.state.request_id = rid
    token = request_id_var.set(rid)
    try:
        response = await call_next(request)
    finally:
        request_id_var.reset(token)
    response.headers["X-Request-ID"] = rid
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all for uncaught errors: log with the request ID and return a
    generic 500 body instead of leaking a stack trace to the client."""
    rid = getattr(request.state, "request_id", "-")
    request_id_var.set(rid)
    logger.error(
        "unhandled exception",
        exc_info=exc,
        extra={"event": "unhandled_exception", "path": request.url.path},
    )
    return JSONResponse(
        status_code=500,
        content={"error": "internal_server_error", "detail": str(exc)},
    )


app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(findings.router)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    """Liveness probe. Returns 200 with basic app metadata.

    Kept dependency-free on purpose so it works before the DB/scanners exist
    and stays usable as a CI/CD readiness check later.
    """
    return {"status": "ok", "app": settings.app_name, "version": "0.1.0"}
