import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.routes.deps import get_current_user, get_request_ip, require_roles
from app.domain.models.user import User
from app.domain.schemas.user import UserCreate, UserListResponse, UserResponse, UserUpdate
from app.infra.database.session import get_db
from app.services.audit_service import audit_service
from app.services.user_service import user_service

router = APIRouter(prefix="/users", tags=["Usuários"])

AdminOrManager = Annotated[User, Depends(require_roles("admin", "manager"))]
AdminOnly = Annotated[User, Depends(require_roles("admin"))]
CurrentUser = Annotated[User, Depends(get_current_user)]


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Criar usuário",
)
def create_user(
    payload: UserCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOnly,
):
    try:
        user = user_service.create(db, payload)
        audit_service.log(
            db,
            action="users.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            resource_type="user",
            resource_id=str(user.id),
            detail={"email": user.email},
            ip_address=get_request_ip(request),
        )
        db.commit()
        db.refresh(user)
        return user
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.get(
    "",
    response_model=UserListResponse,
    summary="Listar usuários",
)
def list_users(
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOrManager,
    is_active: Optional[bool] = Query(None),
    department: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    items, total = user_service.list_users(db, is_active=is_active, department=department, skip=skip, limit=limit)
    return UserListResponse(total=total, items=items)


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Buscar usuário por ID",
)
def get_user(
    user_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: CurrentUser,
):
    if current_user.id != user_id and "admin" not in current_user.role_names and "manager" not in current_user.role_names:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso negado.")
    user = user_service.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")
    return user


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Atualizar usuário",
)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOnly,
):
    user = user_service.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")
    user = user_service.update(db, user, payload)
    audit_service.log(
        db,
        action="users.update",
        actor_id=current_user.id,
        actor_email=current_user.email,
        resource_type="user",
        resource_id=str(user_id),
        ip_address=get_request_ip(request),
    )
    db.commit()
    db.refresh(user)
    return user


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Desativar usuário (soft delete)",
)
def deactivate_user(
    user_id: uuid.UUID,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOnly,
):
    if current_user.id == user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Não é possível desativar a si mesmo.")
    user = user_service.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado.")
    user_service.deactivate(db, user)
    audit_service.log(
        db,
        action="users.deactivate",
        actor_id=current_user.id,
        actor_email=current_user.email,
        resource_type="user",
        resource_id=str(user_id),
        ip_address=get_request_ip(request),
    )
    db.commit()
