"""Service layer for role and permission management."""

import uuid
from typing import Optional

from sqlalchemy.orm import Session

from app.domain.models.role import Permission, Role
from app.domain.schemas.role import PermissionCreate, RoleCreate


class RoleService:
    """Manages RBAC roles and the permissions attached to them."""

    def create(self, db: Session, payload: RoleCreate) -> Role:
        """Create a new role.

        Args:
            db: Active SQLAlchemy session.
            payload: Validated role creation schema.

        Returns:
            The newly created Role instance (not yet committed).

        Raises:
            ValueError: If a role with the same name already exists.
        """
        if db.query(Role).filter(Role.name == payload.name).first():
            raise ValueError(f"Role '{payload.name}' já existe.")
        role = Role(name=payload.name, description=payload.description)
        db.add(role)
        db.flush()
        return role

    def get_by_id(self, db: Session, role_id: uuid.UUID) -> Optional[Role]:
        """Retrieve a role by its UUID.

        Args:
            db: Active SQLAlchemy session.
            role_id: The role's UUID.

        Returns:
            The Role instance, or None if not found.
        """
        return db.query(Role).filter(Role.id == role_id).first()

    def list_roles(
        self,
        db: Session,
        *,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[Role], int]:
        """Return a paginated list of all roles ordered alphabetically.

        Args:
            db: Active SQLAlchemy session.
            skip: Number of records to skip (offset).
            limit: Maximum number of records to return.

        Returns:
            A tuple of (list of Role instances, total count before pagination).
        """
        q = db.query(Role)
        total = q.count()
        items = q.order_by(Role.name).offset(skip).limit(limit).all()
        return items, total

    def add_permission(
        self,
        db: Session,
        role: Role,
        *,
        permission_id: Optional[uuid.UUID] = None,
        permission_data: Optional[PermissionCreate] = None,
    ) -> Role:
        """Attach a permission to a role, creating the permission if necessary.

        Exactly one of ``permission_id`` or ``permission_data`` must be provided.

        Args:
            db: Active SQLAlchemy session.
            role: The Role instance to modify.
            permission_id: UUID of an existing Permission to attach.
            permission_data: Schema for a new Permission to create and attach.

        Returns:
            The updated Role instance (not yet committed).

        Raises:
            ValueError: If neither or both arguments are provided, or if
                ``permission_id`` does not match any existing permission.
        """
        if permission_id:
            perm = db.query(Permission).filter(Permission.id == permission_id).first()
            if not perm:
                raise ValueError("Permissão não encontrada.")
        elif permission_data:
            perm = db.query(Permission).filter(Permission.name == permission_data.name).first()
            if not perm:
                perm = Permission(
                    name=permission_data.name,
                    description=permission_data.description,
                    resource=permission_data.resource,
                    action=permission_data.action,
                )
                db.add(perm)
                db.flush()
        else:
            raise ValueError("Forneça permission_id ou permission.")

        if perm not in role.permissions:
            role.permissions.append(perm)
            db.flush()
        return role

    def remove_permission(
        self,
        db: Session,
        role: Role,
        permission_id: uuid.UUID,
    ) -> Role:
        """Detach a permission from a role.

        Args:
            db: Active SQLAlchemy session.
            role: The Role instance to modify.
            permission_id: UUID of the Permission to detach.

        Returns:
            The updated Role instance (not yet committed).

        Raises:
            ValueError: If the permission does not exist.
        """
        perm = db.query(Permission).filter(Permission.id == permission_id).first()
        if not perm:
            raise ValueError("Permissão não encontrada.")
        if perm in role.permissions:
            role.permissions.remove(perm)
            db.flush()
        return role


role_service = RoleService()
