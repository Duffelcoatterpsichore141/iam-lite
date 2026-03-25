from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import bcrypt as _bcrypt
from jose import JWTError, jwt

from app.core.config import get_settings

settings = get_settings()


def hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def create_access_token(
    subject: str,
    roles: list[str],
    extra_claims: dict[str, Any] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    expire = _now() + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload: dict[str, Any] = {
        "iss": settings.OAUTH2_ISSUER,
        "sub": subject,
        "aud": settings.OAUTH2_AUDIENCE,
        "iat": _now(),
        "exp": expire,
        "token_type": "access",
        "roles": roles,
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(subject: str) -> str:
    expire = _now() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload: dict[str, Any] = {
        "iss": settings.OAUTH2_ISSUER,
        "sub": subject,
        "iat": _now(),
        "exp": expire,
        "token_type": "refresh",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_id_token(
    subject: str,
    email: str,
    name: str,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    expire = _now() + timedelta(minutes=settings.ID_TOKEN_EXPIRE_MINUTES)
    payload: dict[str, Any] = {
        "iss": settings.OAUTH2_ISSUER,
        "sub": subject,
        "aud": settings.OAUTH2_AUDIENCE,
        "iat": _now(),
        "exp": expire,
        "token_type": "id",
        "email": email,
        "name": name,
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        audience=settings.OAUTH2_AUDIENCE,
    )


def decode_refresh_token(token: str) -> dict[str, Any]:
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        options={"verify_aud": False},
    )
