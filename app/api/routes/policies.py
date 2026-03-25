import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.routes.deps import get_request_ip, require_roles
from app.domain.models.user import User
from app.domain.schemas.policy import PolicyCreate, PolicyListResponse, PolicyResponse
from app.infra.database.session import get_db
from app.services.audit_service import audit_service
from app.services.policy_service import policy_service

router = APIRouter(prefix="/policies", tags=["Políticas ABAC"])
AdminOnly = Annotated[User, Depends(require_roles("admin"))]
AdminOrManager = Annotated[User, Depends(require_roles("admin", "manager"))]


@router.post(
    "",
    response_model=PolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Criar política ABAC",
)
def create_policy(
    payload: PolicyCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOnly,
):
    try:
        policy = policy_service.create(db, payload, current_user.id)
        audit_service.log(
            db,
            action="policies.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            resource_type="policy",
            resource_id=str(policy.id),
            detail={"name": policy.name},
            ip_address=get_request_ip(request),
        )
        db.commit()
        db.refresh(policy)
        return policy
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.get(
    "",
    response_model=PolicyListResponse,
    summary="Listar políticas ABAC",
)
def list_policies(
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOrManager,
    is_active: Optional[bool] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    items, total = policy_service.list_policies(db, skip=skip, limit=limit, is_active=is_active)
    return PolicyListResponse(total=total, items=items)


@router.delete(
    "/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remover (desativar) política ABAC",
)
def delete_policy(
    policy_id: uuid.UUID,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOnly,
):
    policy = policy_service.get_by_id(db, policy_id)
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Política não encontrada.")
    policy_service.delete(db, policy)
    audit_service.log(
        db,
        action="policies.delete",
        actor_id=current_user.id,
        actor_email=current_user.email,
        resource_type="policy",
        resource_id=str(policy_id),
        ip_address=get_request_ip(request),
    )
    db.commit()
