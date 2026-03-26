"""REST endpoints for user management (CRUD + deactivation)."""

import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.routes.deps import get_current_user, get_request_ip, require_roles
from app.domain.models.user import User
from app.domain.schemas.user import UserCreate, UserListResponse, UserResponse, UserUpdate
from app.infra.database.session import get_db
from app.services.audit_service import audit_service
from app.services.user_service import user_service

router = APIRouter(prefix="/users", tags=["Usuarios"])

AdminOrManager = Annotated[User, Depends(require_roles("admin", "manager"))]
AdminOnly = Annotated[User, Depends(require_roles("admin"))]
CurrentUser = Annotated[User, Depends(get_current_user)]


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Criar usuario",
)
def create_user(
    payload: UserCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOnly,
) -> UserResponse:
    """Create a new user account.

    Restricted to users with the ``admin`` role.

    Args:
        payload: Validated user creation schema.
        request: Incoming HTTP request used to capture the client IP.
        db: Active SQLAlchemy session.
        current_user: The authenticated admin user performing the action.

    Returns:
        The newly created UserResponse.

    Raises:
        HTTPException: 409 if the email address is already in use.
    """
    try:
        user = user_service.create(db, payload)
        audit_service.log(
            db,
            action="users.create",
            actor_id=current_user.id,
            actor_email=current_user.email,
            resource_type="user",
            resource_id=str(user.id),
            detail={"email": user.email},
            ip_address=get_request_ip(request),
        )
        db.commit()
        db.refresh(user)
        return user
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.get(
    "",
    response_model=UserListResponse,
    summary="Listar usuarios",
)
def list_users(
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOrManager,
    is_active: Optional[bool] = Query(None),
    department: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> UserListResponse:
    """Return a paginated list of users with optional filters.

    Restricted to users with the ``admin`` or ``manager`` role.

    Args:
        db: Active SQLAlchemy session.
        current_user: The authenticated user performing the request.
        is_active: Filter by active status when provided.
        department: Case-insensitive partial match on department name.
        skip: Number of records to skip.
        limit: Maximum number of records to return.

    Returns:
        A UserListResponse containing total count and a list of UserResponse items.
    """
    items, total = user_service.list_users(
        db,
        is_active=is_active,
        department=department,
        skip=skip,
        limit=limit,
    )
    return UserListResponse(total=total, items=items)


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Buscar usuario por ID",
)
def get_user(
    user_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: CurrentUser,
) -> UserResponse:
    """Retrieve a single user by UUID.

    Regular users may only retrieve their own profile; admins and managers
    may retrieve any user.

    Args:
        user_id: UUID of the user to retrieve.
        db: Active SQLAlchemy session.
        current_user: The authenticated user performing the request.

    Returns:
        The requested UserResponse.

    Raises:
        HTTPException: 403 if a non-admin/manager requests another user's profile.
        HTTPException: 404 if the user does not exist.
    """
    is_privileged = (
        "admin" in current_user.role_names or "manager" in current_user.role_names
    )
    if current_user.id != user_id and not is_privileged:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso negado.")

    user = user_service.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario nao encontrado.")
    return user


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Atualizar usuario",
)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOnly,
) -> UserResponse:
    """Apply a partial update to an existing user.

    Restricted to users with the ``admin`` role.

    Args:
        user_id: UUID of the user to update.
        payload: Partial update schema; only non-None fields are applied.
        request: Incoming HTTP request used to capture the client IP.
        db: Active SQLAlchemy session.
        current_user: The authenticated admin user performing the action.

    Returns:
        The updated UserResponse.

    Raises:
        HTTPException: 404 if the user does not exist.
    """
    user = user_service.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario nao encontrado.")
    user = user_service.update(db, user, payload)
    audit_service.log(
        db,
        action="users.update",
        actor_id=current_user.id,
        actor_email=current_user.email,
        resource_type="user",
        resource_id=str(user_id),
        ip_address=get_request_ip(request),
    )
    db.commit()
    db.refresh(user)
    return user


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Desativar usuario (soft delete)",
)
def deactivate_user(
    user_id: uuid.UUID,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: AdminOnly,
) -> None:
    """Soft-delete a user by setting their account to inactive.

    Restricted to users with the ``admin`` role. An admin cannot deactivate
    their own account.

    Args:
        user_id: UUID of the user to deactivate.
        request: Incoming HTTP request used to capture the client IP.
        db: Active SQLAlchemy session.
        current_user: The authenticated admin user performing the action.

    Raises:
        HTTPException: 400 if the admin attempts to deactivate themselves.
        HTTPException: 404 if the user does not exist.
    """
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nao e possivel desativar a si mesmo.",
        )
    user = user_service.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario nao encontrado.")
    user_service.deactivate(db, user)
    audit_service.log(
        db,
        action="users.deactivate",
        actor_id=current_user.id,
        actor_email=current_user.email,
        resource_type="user",
        resource_id=str(user_id),
        ip_address=get_request_ip(request),
    )
    db.commit()
