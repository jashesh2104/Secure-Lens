"""Authentication endpoints: register a user and log in for a JWT.

Passwords are hashed with bcrypt (via passlib) and never stored in plaintext.
Both endpoints return a signed JWT that protected routes accept through the
`require_auth` dependency in `app.core.security`, so the frontend can register
and immediately be authenticated without a second round-trip.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import create_access_token
from app.database import get_db
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["auth"])

# bcrypt via passlib. `deprecated="auto"` lets us add stronger schemes later
# and transparently rehash old passwords on next login.
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class RegisterRequest(BaseModel):
    """New-account payload. bcrypt only hashes the first 72 bytes, so we cap
    the password length there to reject silently-truncated input up front."""

    username: str = Field(min_length=3, max_length=150)
    password: str = Field(min_length=8, max_length=72)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """Create a user with a bcrypt-hashed password and return a JWT."""
    existing = db.scalar(select(User).where(User.username == payload.username))
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already taken")

    user = User(
        username=payload.username,
        hashed_password=_pwd_context.hash(payload.password),
    )
    db.add(user)
    db.commit()
    return TokenResponse(access_token=create_access_token(user.username))


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """Verify credentials and return a JWT, or 401 on any mismatch.

    The same 401 is used for unknown user and bad password so we don't leak
    which usernames exist.
    """
    user = db.scalar(select(User).where(User.username == payload.username))
    if user is None or not _pwd_context.verify(payload.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    return TokenResponse(access_token=create_access_token(user.username))
