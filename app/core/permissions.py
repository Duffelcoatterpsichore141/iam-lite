from enum import StrEnum


class SystemAction(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    APPROVE = "approve"


class ResourceClassification(StrEnum):
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
    perms: set[str] = set()
    for role in roles:
        perms.update(ROLE_PERMISSIONS.get(role, []))
    return perms


def has_permission(roles: list[str], permission: str) -> bool:
    return permission in get_permissions_for_roles(roles)
