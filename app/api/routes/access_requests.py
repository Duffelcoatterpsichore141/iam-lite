import uuid
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.routes.deps import get_current_user, get_request_ip, require_roles
from app.domain.models.access_request import AccessRequest
from app.domain.models.system import System
from app.domain.models.user import User
from app.domain.schemas.access_request import (
    AccessRequestCreate,
    AccessRequestListResponse,
    AccessRequestResponse,
    ReviewRequest,
)
from app.infra.database.session import get_db
from app.services.audit_service import audit_service
from app.services.policy_service import policy_service

router = APIRouter(prefix="/access-requests", tags=["Solicitações de Acesso"])
AnyAuth = Annotated[User, Depends(get_current_user)]
Approver = Annotated[User, Depends(require_roles("admin", "manager"))]


@router.post(
    "",
    response_model=AccessRequestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Solicitar acesso a um sistema",
)
def create_access_request(
    payload: AccessRequestCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: AnyAuth,
):
    system = db.query(System).filter(System.id == payload.system_id, System.is_active.is_(True)).first()
    if not system:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sistema não encontrado.")

    existing = (
        db.query(AccessRequest)
        .filter(
            AccessRequest.requester_id == current_user.id,
            AccessRequest.system_id == system.id,
            AccessRequest.status == "pending",
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Já existe uma solicitação pendente para este sistema.",
        )

    all_policies = db.query(__import__("app.domain.models.policy", fromlist=["Policy"]).Policy).filter_by(is_active=True).all()
    resource_attrs = {
        "classification": system.classification,
        "owner_department": system.owner_department,
        "slug": system.slug,
    }
    abac_allowed = policy_service.evaluate(current_user, resource_attrs, "access", all_policies)

    user_role_names = {r.name for r in current_user.roles}
    rbac_allowed = bool(user_role_names.intersection({"admin", "manager"}))

    initial_status = "pending"
    if not system.requires_approval and (rbac_allowed or abac_allowed):
        initial_status = "approved"

    ar = AccessRequest(
        requester_id=current_user.id,
        system_id=system.id,
        requested_role_id=payload.requested_role_id,
        justification=payload.justification,
        status=initial_status,
    )
    db.add(ar)
    db.flush()

    audit_service.log(
        db,
        action="access_request.create",
        actor_id=current_user.id,
        actor_email=current_user.email,
        resource_type="access_request",
        resource_id=str(ar.id),
        system_id=system.id,
        detail={"system": system.slug, "status": initial_status},
        ip_address=get_request_ip(request),
    )
    db.commit()
    db.refresh(ar)
    return ar


@router.get(
    "",
    response_model=AccessRequestListResponse,
    summary="Listar solicitações de acesso",
)
def list_access_requests(
    db: Annotated[Session, Depends(get_db)],
    current_user: AnyAuth,
    status_filter: Optional[str] = Query(None, alias="status"),
    system_id: Optional[uuid.UUID] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    q = db.query(AccessRequest)
    is_approver = bool({"admin", "manager"}.intersection(current_user.role_names))
    if not is_approver:
        q = q.filter(AccessRequest.requester_id == current_user.id)
    if status_filter:
        q = q.filter(AccessRequest.status == status_filter)
    if system_id:
        q = q.filter(AccessRequest.system_id == system_id)
    total = q.count()
    items = q.order_by(AccessRequest.created_at.desc()).offset(skip).limit(limit).all()
    return AccessRequestListResponse(total=total, items=items)


@router.patch(
    "/{request_id}/approve",
    response_model=AccessRequestResponse,
    summary="Aprovar solicitação de acesso",
)
def approve_access_request(
    request_id: uuid.UUID,
    payload: ReviewRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: Approver,
):
    ar = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
    if not ar:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Solicitação não encontrada.")
    if ar.status != "pending":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Solicitação já está '{ar.status}'.")

    ar.status = "approved"
    ar.reviewer_id = current_user.id
    ar.reviewer_comment = payload.comment
    ar.reviewed_at = datetime.now(timezone.utc)

    if ar.requested_role_id:
        requester = db.query(User).filter(User.id == ar.requester_id).first()
        from app.domain.models.role import Role
        role = db.query(Role).filter(Role.id == ar.requested_role_id).first()
        if requester and role and role not in requester.roles:
            requester.roles.append(role)

    audit_service.log(
        db,
        action="access_request.approve",
        actor_id=current_user.id,
        actor_email=current_user.email,
        resource_type="access_request",
        resource_id=str(request_id),
        system_id=ar.system_id,
        detail={"comment": payload.comment},
        ip_address=get_request_ip(request),
    )
    db.commit()
    db.refresh(ar)
    return ar


@router.patch(
    "/{request_id}/reject",
    response_model=AccessRequestResponse,
    summary="Reprovar solicitação de acesso",
)
def reject_access_request(
    request_id: uuid.UUID,
    payload: ReviewRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: Approver,
):
    ar = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
    if not ar:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Solicitação não encontrada.")
    if ar.status != "pending":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Solicitação já está '{ar.status}'.")

    ar.status = "rejected"
    ar.reviewer_id = current_user.id
    ar.reviewer_comment = payload.comment
    ar.reviewed_at = datetime.now(timezone.utc)

    audit_service.log(
        db,
        action="access_request.reject",
        actor_id=current_user.id,
        actor_email=current_user.email,
        resource_type="access_request",
        resource_id=str(request_id),
        system_id=ar.system_id,
        detail={"comment": payload.comment},
        ip_address=get_request_ip(request),
    )
    db.commit()
    db.refresh(ar)
    return ar
