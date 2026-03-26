"""Service layer for user management operations."""

import uuid
from typing import Optional

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password
from app.domain.models.role import Role
from app.domain.models.user import User
from app.domain.schemas.user import UserCreate, UserUpdate
from app.infra.redis.client import token_store


class UserService:
    """Handles business logic for creating, querying, updating and deactivating users."""

    def create(self, db: Session, payload: UserCreate) -> User:
        """Create a new user and persist it to the database.

        Args:
            db: Active SQLAlchemy session.
            payload: Validated user creation schema.

        Returns:
            The newly created User instance (not yet committed).

        Raises:
            ValueError: If the email is already in use or any role_id is invalid.
        """
        if db.query(User).filter(User.email == payload.email).first():
            raise ValueError(f"Email '{payload.email}' já está em uso.")

        roles: list[Role] = []
        if payload.role_ids:
            roles = db.query(Role).filter(Role.id.in_(payload.role_ids)).all()
            if len(roles) != len(payload.role_ids):
                raise ValueError("Um ou mais role_ids são inválidos.")

        user = User(
            email=payload.email,
            full_name=payload.full_name,
            hashed_password=hash_password(payload.password),
            department=payload.department,
            location=payload.location,
            manager_id=payload.manager_id,
        )
        user.roles = roles
        db.add(user)
        db.flush()
        return user

    def get_by_id(self, db: Session, user_id: uuid.UUID) -> Optional[User]:
        """Retrieve a user by their UUID.

        Args:
            db: Active SQLAlchemy session.
            user_id: The user's UUID.

        Returns:
            The User instance, or None if not found.
        """
        return db.query(User).filter(User.id == user_id).first()

    def get_by_email(self, db: Session, email: str) -> Optional[User]:
        """Retrieve a user by their email address.

        Args:
            db: Active SQLAlchemy session.
            email: The user's email address.

        Returns:
            The User instance, or None if not found.
        """
        return db.query(User).filter(User.email == email).first()

    def authenticate(self, db: Session, email: str, password: str) -> Optional[User]:
        """Verify credentials and return the user if valid and active.

        Args:
            db: Active SQLAlchemy session.
            email: Candidate email address.
            password: Plain-text password to verify.

        Returns:
            The authenticated User instance, or None on failure.
        """
        user = self.get_by_email(db, email)
        if not user or not user.is_active:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user

    def list_users(
        self,
        db: Session,
        *,
        is_active: Optional[bool] = None,
        department: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[User], int]:
        """Return a paginated list of users with optional filters.

        Args:
            db: Active SQLAlchemy session.
            is_active: Filter by active status when provided.
            department: Case-insensitive partial match on department name.
            skip: Number of records to skip (offset).
            limit: Maximum number of records to return.

        Returns:
            A tuple of (list of User instances, total count before pagination).
        """
        q = db.query(User)
        if is_active is not None:
            q = q.filter(User.is_active == is_active)
        if department:
            q = q.filter(User.department.ilike(f"%{department}%"))
        total = q.count()
        items = q.order_by(User.created_at.desc()).offset(skip).limit(limit).all()
        return items, total

    def update(self, db: Session, user: User, payload: UserUpdate) -> User:
        """Apply partial updates to an existing user.

        Invalidates the permission cache when roles are changed.

        Args:
            db: Active SQLAlchemy session.
            user: The User instance to update.
            payload: Validated partial-update schema. Only non-None fields are applied.

        Returns:
            The updated User instance (not yet committed).
        """
        if payload.full_name is not None:
            user.full_name = payload.full_name
        if payload.department is not None:
            user.department = payload.department
        if payload.location is not None:
            user.location = payload.location
        if payload.manager_id is not None:
            user.manager_id = payload.manager_id
        if payload.is_active is not None:
            user.is_active = payload.is_active
        if payload.role_ids is not None:
            roles = db.query(Role).filter(Role.id.in_(payload.role_ids)).all()
            user.roles = roles
            token_store.invalidate_permission_cache(str(user.id))
        db.flush()
        return user

    def deactivate(self, db: Session, user: User) -> User:
        """Soft-delete a user by setting is_active to False.

        Also invalidates the user's cached permissions in Redis.

        Args:
            db: Active SQLAlchemy session.
            user: The User instance to deactivate.

        Returns:
            The deactivated User instance (not yet committed).
        """
        user.is_active = False
        token_store.invalidate_permission_cache(str(user.id))
        db.flush()
        return user


user_service = UserService()
