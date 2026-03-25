import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.routes.deps import get_current_user, get_request_ip, require_roles
from app.domain.models.system import System
from app.domain.models.user import User
from app.domain.schemas.system import SystemCreate, SystemListResponse, SystemResponse
from app.infra.database.session import get_db
from app.services.audit_service import audit_service

router = APIRouter(prefix="/systems", tags=["Sistemas"])
AdminOnly = Annotated[User, Depends(require_roles("admin"))]
AnyAuth = Annotated[User, Depends(get_current_user)]


@router.post(
    "",
    response_model=SystemResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastrar sistema fictício",
)
def create_system(
    payload: SystemCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOnly,
):
    existing = db.query(System).filter(System.slug == payload.slug).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Sistema com slug '{payload.slug}' já existe.")
    system = System(
        name=payload.name,
        slug=payload.slug,
        description=payload.description,
        classification=payload.classification,
        owner_department=payload.owner_department,
        requires_approval=payload.requires_approval,
    )
    db.add(system)
    db.flush()
    audit_service.log(
        db,
        action="systems.create",
        actor_id=current_user.id,
        actor_email=current_user.email,
        resource_type="system",
        resource_id=str(system.id),
        system_id=system.id,
        detail={"name": system.name, "classification": system.classification},
        ip_address=get_request_ip(request),
    )
    db.commit()
    db.refresh(system)
    return system


@router.get(
    "",
    response_model=SystemListResponse,
    summary="Listar sistemas disponíveis",
)
def list_systems(
    db: Annotated[Session, Depends(get_db)],
    current_user: AnyAuth,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    q = db.query(System).filter(System.is_active.is_(True))
    total = q.count()
    items = q.order_by(System.name).offset(skip).limit(limit).all()
    return SystemListResponse(total=total, items=items)
