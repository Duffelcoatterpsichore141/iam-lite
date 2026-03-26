"""Service layer for creating and querying immutable audit log entries."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.domain.models.audit_log import AuditLog


class AuditService:
    """Writes and queries audit log records in compliance with LGPD requirements.

    Audit entries are immutable — no update or delete operations are exposed.
    """

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
        """Persist a single audit log entry.

        Args:
            db: Active SQLAlchemy session.
            action: Dot-separated action identifier (e.g. ``auth.login.success``).
            actor_id: UUID of the user who performed the action, if known.
            actor_email: Email of the actor, used when actor_id is unavailable.
            resource_type: Type of the resource affected (e.g. ``user``, ``role``).
            resource_id: String identifier of the affected resource.
            system_id: UUID of the target managed system, if applicable.
            status: Outcome of the action — ``"success"`` or ``"failure"``.
            detail: Arbitrary JSON-serialisable metadata about the event.
            ip_address: IP address of the originating request.
            user_agent: User-Agent header from the originating request.

        Returns:
            The persisted AuditLog instance (not yet committed).
        """
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
        """Query audit log entries with optional filters and pagination.

        Args:
            db: Active SQLAlchemy session.
            actor_id: Filter by the UUID of the acting user.
            actor_email: Case-insensitive partial match on actor email.
            action: Case-insensitive partial match on the action string.
            resource_type: Exact match on resource type.
            system_id: Filter by managed system UUID.
            status: Exact match on outcome status.
            date_from: Return only entries at or after this timestamp.
            date_to: Return only entries at or before this timestamp.
            skip: Number of records to skip (offset).
            limit: Maximum number of records to return.

        Returns:
            A tuple of (list of AuditLog instances, total count before pagination).
        """
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
