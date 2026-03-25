import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.domain.models.audit_log import AuditLog


class AuditService:
    def log(
        self,
        db: Session,
        *,
        action: str,
        actor_id: Optional[uuid.UUID] = None,
        actor_email: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        system_id: Optional[uuid.UUID] = None,
        status: str = "success",
        detail: Optional[dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditLog:
        entry = AuditLog(
            actor_id=actor_id,
            actor_email=actor_email,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            system_id=system_id,
            status=status,
            detail=detail or {},
            ip_address=ip_address,
            user_agent=user_agent,
        )
        db.add(entry)
        db.flush()
        return entry

    def query_logs(
        self,
        db: Session,
        *,
        actor_id: Optional[uuid.UUID] = None,
        actor_email: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        system_id: Optional[uuid.UUID] = None,
        status: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[AuditLog], int]:
        q = db.query(AuditLog)

        if actor_id:
            q = q.filter(AuditLog.actor_id == actor_id)
        if actor_email:
            q = q.filter(AuditLog.actor_email.ilike(f"%{actor_email}%"))
        if action:
            q = q.filter(AuditLog.action.ilike(f"%{action}%"))
        if resource_type:
            q = q.filter(AuditLog.resource_type == resource_type)
        if system_id:
            q = q.filter(AuditLog.system_id == system_id)
        if status:
            q = q.filter(AuditLog.status == status)
        if date_from:
            q = q.filter(AuditLog.created_at >= date_from)
        if date_to:
            q = q.filter(AuditLog.created_at <= date_to)

        total = q.count()
        items = q.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit).all()
        return items, total


audit_service = AuditService()
