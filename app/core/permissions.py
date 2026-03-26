"""Static permission definitions for RBAC evaluation."""

from enum import StrEnum


class SystemAction(StrEnum):
    """Enumeration of allowed actions on managed systems."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    APPROVE = "approve"


class ResourceClassification(StrEnum):
    """Data sensitivity classification levels for managed resources."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    CRITICAL = "critical"


ROLE_PERMISSIONS: dict[str, list[str]] = {
    "admin": [
        "users:read", "users:write", "users:delete",
        "roles:read", "roles:write", "roles:delete",
        "policies:read", "policies:write", "policies:delete",
        "systems:read", "systems:write",
        "access_requests:read", "access_requests:approve",
        "audit:read",
    ],
    "manager": [
        "users:read", "users:write",
        "roles:read",
        "policies:read",
        "systems:read",
        "access_requests:read", "access_requests:approve",
        "audit:read",
    ],
    "viewer": [
        "users:read",
        "roles:read",
        "systems:read",
        "access_requests:read",
    ],
}


def get_permissions_for_roles(roles: list[str]) -> set[str]:
    """Aggregate the full permission set for a list of role names.

    Args:
        roles: List of role name strings (e.g. ``["admin", "viewer"]``).

    Returns:
        The union of all permissions granted by the given roles.
    """
    perms: set[str] = set()
    for role in roles:
        perms.update(ROLE_PERMISSIONS.get(role, []))
    return perms


def has_permission(roles: list[str], permission: str) -> bool:
    """Check whether any of the given roles grant a specific permission.

    Args:
        roles: List of role name strings held by the subject.
        permission: The permission string to check (e.g. ``"users:write"``).

    Returns:
        True if the permission is granted by at least one of the roles.
    """
    return permission in get_permissions_for_roles(roles)
