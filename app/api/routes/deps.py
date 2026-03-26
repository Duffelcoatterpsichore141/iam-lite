"""FastAPI dependency functions for authentication, authorisation, and request metadata."""

import uuid
from typing import Annotated, Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.security import decode_token
from app.domain.models.user import User
from app.infra.database.session import get_db
from app.infra.redis.client import token_store
from app.services.user_service import user_service

bearer = HTTPBearer(auto_error=True)


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Decode a Bearer JWT and return the corresponding active user.

    Args:
        credentials: HTTP Bearer credentials extracted from the Authorization header.
        db: Active SQLAlchemy session.

    Returns:
        The authenticated and active User instance.

    Raises:
        HTTPException: 401 if the token is invalid, expired, revoked, or the
            associated user is inactive or not found.
    """
    token = credentials.credentials
    try:
        payload = decode_token(token)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalido ou expirado.",
        ) from exc

    jti = payload.get("jti") or payload.get("sub")
    if jti and token_store.is_revoked(token[:32]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token revogado.",
        )

    sub = payload.get("sub")
    if not sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token sem sujeito.",
        )

    try:
        user_id = uuid.UUID(sub)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sujeito invalido.",
        ) from exc

    user = user_service.get_by_id(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario nao encontrado ou inativo.",
        )

    return user


def require_roles(*required_roles: str) -> Callable[[User], User]:
    """Return a dependency that enforces role-based access control.

    Args:
        *required_roles: One or more role names. The current user must hold
            at least one of them to pass the check.

    Returns:
        A FastAPI dependency callable that resolves to the current User or
        raises a 403 HTTPException.
    """
    def checker(current_user: Annotated[User, Depends(get_current_user)]) -> User:
        user_role_names = {r.name for r in current_user.roles}
        if not user_role_names.intersection(required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Acesso negado. Roles necessarias: {list(required_roles)}.",
            )
        return current_user

    return checker


def get_request_ip(request: Request) -> str | None:
    """Extract the originating IP address from the request.

    Respects the ``X-Forwarded-For`` header when the service runs behind a proxy.

    Args:
        request: The incoming FastAPI/Starlette request object.

    Returns:
        The client IP address string, or None if it cannot be determined.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def get_user_agent(request: Request) -> str | None:
    """Extract the User-Agent header value from the request.

    Args:
        request: The incoming FastAPI/Starlette request object.

    Returns:
        The User-Agent string, or None if the header is absent.
    """
    return request.headers.get("User-Agent")
