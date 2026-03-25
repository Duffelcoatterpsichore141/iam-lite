import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.routes.deps import get_request_ip, require_roles
from app.domain.models.user import User
from app.domain.schemas.role import AddPermissionRequest, RoleCreate, RoleListResponse, RoleResponse
from app.infra.database.session import get_db
from app.services.audit_service import audit_service
from app.services.role_service import role_service

router = APIRouter(prefix="/roles", tags=["Roles & Permissões"])
AdminOnly = Annotated[User, Depends(require_roles("admin"))]
AdminOrManager = Annotated[User, Depends(require_roles("admin", "manager"))]


@router.post(
    "",
    response_model=RoleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Criar role",
)
def create_role(
    payload: RoleCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOnly,
):
    try:
        role = role_service.create(db, payload)
        audit_service.log(
            db,
            action="roles.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            resource_type="role",
            resource_id=str(role.id),
            detail={"name": role.name},
            ip_address=get_request_ip(request),
        )
        db.commit()
        db.refresh(role)
        return role
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.get(
    "",
    response_model=RoleListResponse,
    summary="Listar roles",
)
def list_roles(
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOrManager,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    items, total = role_service.list_roles(db, skip=skip, limit=limit)
    return RoleListResponse(total=total, items=items)


@router.post(
    "/{role_id}/permissions",
    response_model=RoleResponse,
    summary="Adicionar permissão à role",
)
def add_permission(
    role_id: uuid.UUID,
    payload: AddPermissionRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOnly,
):
    role = role_service.get_by_id(db, role_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role não encontrada.")
    try:
        role = role_service.add_permission(
            db,
            role,
            permission_id=payload.permission_id,
            permission_data=payload.permission,
        )
        audit_service.log(
            db,
            action="roles.permission.add",
            actor_id=current_user.id,
            actor_email=current_user.email,
            resource_type="role",
            resource_id=str(role_id),
            ip_address=get_request_ip(request),
        )
        db.commit()
        db.refresh(role)
        return role
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.delete(
    "/{role_id}/permissions/{perm_id}",
    response_model=RoleResponse,
    summary="Remover permissão da role",
)
def remove_permission(
    role_id: uuid.UUID,
    perm_id: uuid.UUID,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOnly,
):
    role = role_service.get_by_id(db, role_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role não encontrada.")
    try:
        role = role_service.remove_permission(db, role, perm_id)
        audit_service.log(
            db,
            action="roles.permission.remove",
            actor_id=current_user.id,
            actor_email=current_user.email,
            resource_type="role",
            resource_id=str(role_id),
            ip_address=get_request_ip(request),
        )
        db.commit()
        db.refresh(role)
        return role
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
