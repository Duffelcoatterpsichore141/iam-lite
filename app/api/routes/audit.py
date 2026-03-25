import uuid
from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.routes.deps import require_roles
from app.domain.models.user import User
from app.domain.schemas.audit_log import AuditLogListResponse
from app.infra.database.session import get_db
from app.services.audit_service import audit_service

router = APIRouter(prefix="/audit", tags=["Auditoria"])
AdminOrManager = Annotated[User, Depends(require_roles("admin", "manager"))]


@router.get(
    "/logs",
    response_model=AuditLogListResponse,
    summary="Consultar trilha de auditoria (imutável)",
    description=(
        "Retorna logs de auditoria com filtros. "
        "**Os logs nunca podem ser editados ou deletados via API** — conformidade LGPD."
    ),
)
def get_audit_logs(
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOrManager,
    actor_id: Optional[uuid.UUID] = Query(None, description="Filtrar por ID do ator"),
    actor_email: Optional[str] = Query(None, description="Filtrar por e-mail do ator (parcial)"),
    action: Optional[str] = Query(None, description="Filtrar por ação (parcial)"),
    resource_type: Optional[str] = Query(None),
    system_id: Optional[uuid.UUID] = Query(None),
    status: Optional[str] = Query(None, pattern="^(success|failure)$"),
    date_from: Optional[datetime] = Query(None, description="ISO 8601"),
    date_to: Optional[datetime] = Query(None, description="ISO 8601"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
):
    items, total = audit_service.query_logs(
        db,
        actor_id=actor_id,
        actor_email=actor_email,
        action=action,
        resource_type=resource_type,
        system_id=system_id,
        status=status,
        date_from=date_from,
        date_to=date_to,
        skip=skip,
        limit=limit,
    )
    return AuditLogListResponse(total=total, items=items)
