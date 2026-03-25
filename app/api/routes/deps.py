import uuid
from typing import Annotated

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
    token = credentials.credentials
    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido ou expirado.")

    jti = payload.get("jti") or payload.get("sub")
    if jti and token_store.is_revoked(token[:32]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revogado.")

    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token sem sujeito.")

    try:
        user_id = uuid.UUID(sub)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sujeito inválido.")

    user = user_service.get_by_id(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário não encontrado ou inativo.")

    return user


def require_roles(*required_roles: str):
    def checker(current_user: Annotated[User, Depends(get_current_user)]) -> User:
        user_role_names = {r.name for r in current_user.roles}
        if not user_role_names.intersection(required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Acesso negado. Roles necessárias: {list(required_roles)}.",
            )
        return current_user
    return checker


def get_request_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def get_user_agent(request: Request) -> str | None:
    return request.headers.get("User-Agent")
