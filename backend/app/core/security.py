"""JWT auth helpers (HS256). Minimal by design: issue and verify bearer tokens.

Not yet wired into routers — endpoints stay open in dev. Wire `require_auth`
as a dependency on protected routes when auth is enabled. Secret/expiry come
from settings so prod overrides via env.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import get_settings

settings = get_settings()
_ALGO = "HS256"
_bearer = HTTPBearer(auto_error=False)


def create_access_token(subject: str, expires_minutes: int = 60) -> str:
    """Issue a signed JWT for the given subject (e.g. username)."""
    now = datetime.now(timezone.utc)
    payload = {"sub": subject, "iat": now, "exp": now + timedelta(minutes=expires_minutes)}
    return jwt.encode(payload, settings.jwt_secret, algorithm=_ALGO)


def require_auth(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> str:
    """Dependency: validate the bearer token, return the subject, else 401."""
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    try:
        payload = jwt.decode(creds.credentials, settings.jwt_secret, algorithms=[_ALGO])
        return payload["sub"]
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from exc
