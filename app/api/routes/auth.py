"""OAuth2-compatible authentication endpoints (token, refresh, introspect, revoke)."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import (
    create_access_token,
    create_id_token,
    create_refresh_token,
    decode_refresh_token,
    decode_token,
)
from app.domain.models.user import User
from app.domain.schemas.auth import (
    IntrospectRequest,
    IntrospectResponse,
    RevokeRequest,
    TokenRequest,
    TokenResponse,
)
from app.infra.database.session import get_db
from app.infra.redis.client import token_store
from app.services.audit_service import audit_service
from app.services.user_service import user_service

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["Autenticacao"])


def _build_token_response(user: User, include_id_token: bool = False) -> TokenResponse:
    """Build a TokenResponse for a given user, storing the refresh token in Redis.

    Args:
        user: The authenticated User instance.
        include_id_token: When True, an OpenID Connect id_token is included.

    Returns:
        A TokenResponse containing the issued tokens and metadata.
    """
    roles = [r.name for r in user.roles]
    access = create_access_token(str(user.id), roles)
    refresh = create_refresh_token(str(user.id))
    ttl = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
    token_store.store_refresh_token(str(user.id), refresh, ttl)
    id_tok = None
    if include_id_token:
        id_tok = create_id_token(
            str(user.id),
            user.email,
            user.full_name,
            {"department": user.department, "location": user.location},
        )
    return TokenResponse(
        access_token=access,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_token=refresh,
        id_token=id_tok,
        scope="openid profile email" if include_id_token else None,
    )


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Login OAuth2 - Password / Client Credentials",
    description=(
        "Emite access_token, refresh_token e (opcionalmente) id_token.\n\n"
        "**grant_type=password** -- use email/senha.\n\n"
        "**grant_type=client_credentials** -- use client_id/client_secret (futuro)."
    ),
)
def login(
    payload: TokenRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate a user and issue OAuth2 tokens.

    Args:
        payload: Token request body containing grant_type and credentials.
        request: Incoming HTTP request used to capture the client IP.
        db: Active SQLAlchemy session.

    Returns:
        A TokenResponse with access, refresh, and optionally id tokens.

    Raises:
        HTTPException: 400 if credentials are missing or grant_type is unsupported.
        HTTPException: 401 if credentials are invalid.
    """
    if payload.grant_type != "password":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"grant_type '{payload.grant_type}' nao suportado.",
        )

    if not payload.username or not payload.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="username e password obrigatorios.",
        )

    user = user_service.authenticate(db, payload.username, payload.password)
    if not user:
        audit_service.log(
            db,
            action="auth.login.failed",
            actor_email=payload.username,
            status="failure",
            ip_address=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais invalidas.",
        )

    include_id = bool(payload.scope and "openid" in payload.scope)
    resp = _build_token_response(user, include_id_token=include_id)
    audit_service.log(
        db,
        action="auth.login.success",
        actor_id=user.id,
        actor_email=user.email,
        status="success",
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    return resp


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Renovar access token",
)
def refresh(payload: TokenRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """Issue a new access token using a valid refresh token.

    Args:
        payload: Token request body containing the refresh_token field.
        db: Active SQLAlchemy session.

    Returns:
        A new TokenResponse with a fresh access token.

    Raises:
        HTTPException: 400 if refresh_token is missing.
        HTTPException: 401 if the token is invalid, revoked, or the user is inactive.
    """
    if not payload.refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="refresh_token obrigatorio.",
        )

    try:
        claims = decode_refresh_token(payload.refresh_token)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="refresh_token invalido.",
        ) from exc

    if claims.get("token_type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token nao e do tipo refresh.",
        )

    sub = claims.get("sub")
    stored = token_store.get_refresh_token(sub)
    if stored != payload.refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="refresh_token revogado ou nao encontrado.",
        )

    user = user_service.get_by_id(db, uuid.UUID(sub))
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario inativo.",
        )

    return _build_token_response(user)


@router.post(
    "/introspect",
    response_model=IntrospectResponse,
    summary="Validar token (RFC 7662)",
)
def introspect(payload: IntrospectRequest) -> IntrospectResponse:
    """Validate a token and return its claims following RFC 7662.

    Args:
        payload: Request body containing the token string to validate.

    Returns:
        An IntrospectResponse with active=True and token claims on success,
        or active=False when the token is invalid or expired.
    """
    try:
        claims = decode_token(payload.token)
        return IntrospectResponse(
            active=True,
            sub=claims.get("sub"),
            email=claims.get("email"),
            roles=claims.get("roles"),
            exp=claims.get("exp"),
            iat=claims.get("iat"),
            iss=claims.get("iss"),
            aud=claims.get("aud") if isinstance(claims.get("aud"), str) else None,
            token_type=claims.get("token_type"),
        )
    except JWTError:
        return IntrospectResponse(active=False)


@router.post(
    "/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revogar token",
)
def revoke(payload: RevokeRequest, db: Session = Depends(get_db)) -> None:
    """Revoke an active token, preventing further use.

    Silently succeeds if the token is already invalid or expired so that
    callers do not need to handle token-state edge cases.

    Args:
        payload: Request body containing the token to revoke.
        db: Active SQLAlchemy session.
    """
    try:
        claims = decode_token(payload.token)
        sub = claims.get("sub")
        token_store.delete_refresh_token(sub)
        token_store.revoke_token(
            payload.token[:32],
            ttl_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
        audit_service.log(
            db,
            action="auth.token.revoked",
            actor_email=claims.get("email"),
            status="success",
        )
        db.commit()
    except JWTError:
        pass
