import uuid
from typing import Optional

from sqlalchemy.orm import Session

from app.domain.models.role import Permission, Role
from app.domain.schemas.role import PermissionCreate, RoleCreate


class RoleService:
    def create(self, db: Session, payload: RoleCreate) -> Role:
        if db.query(Role).filter(Role.name == payload.name).first():
            raise ValueError(f"Role '{payload.name}' já existe.")
        role = Role(name=payload.name, description=payload.description)
        db.add(role)
        db.flush()
        return role

    def get_by_id(self, db: Session, role_id: uuid.UUID) -> Optional[Role]:
        return db.query(Role).filter(Role.id == role_id).first()

    def list_roles(
        self, db: Session, *, skip: int = 0, limit: int = 50
    ) -> tuple[list[Role], int]:
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
        if permission_id:
            perm = db.query(Permission).filter(Permission.id == permission_id).first()
            if not perm:
                raise ValueError("Permissão não encontrada.")
        elif permission_data:
            existing = db.query(Permission).filter(Permission.name == permission_data.name).first()
            if existing:
                perm = existing
            else:
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

    def remove_permission(self, db: Session, role: Role, permission_id: uuid.UUID) -> Role:
        perm = db.query(Permission).filter(Permission.id == permission_id).first()
        if not perm:
            raise ValueError("Permissão não encontrada.")
        if perm in role.permissions:
            role.permissions.remove(perm)
            db.flush()
        return role


role_service = RoleService()
