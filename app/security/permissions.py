"""Role permissions for authenticated SafeNest users and simulated actions."""

from enum import StrEnum


class UserRole(StrEnum):
    USER = "USER"
    ADMIN = "ADMIN"


class Permission(StrEnum):
    VIEW_EMERGENCY = "VIEW_EMERGENCY"
    REQUEST_HIGH_IMPACT_ACTION = "REQUEST_HIGH_IMPACT_ACTION"
    APPROVE_HIGH_IMPACT_ACTION = "APPROVE_HIGH_IMPACT_ACTION"
    EXECUTE_APPROVED_ACTION = "EXECUTE_APPROVED_ACTION"
    MANAGE_ROLES = "MANAGE_ROLES"


ROLE_PERMISSIONS: dict[UserRole, frozenset[Permission]] = {
    UserRole.USER: frozenset(
        {
            Permission.VIEW_EMERGENCY,
            Permission.REQUEST_HIGH_IMPACT_ACTION,
            Permission.APPROVE_HIGH_IMPACT_ACTION,
            Permission.EXECUTE_APPROVED_ACTION,
        }
    ),
    UserRole.ADMIN: frozenset(Permission),
}


def has_permission(role: UserRole | str, permission: Permission) -> bool:
    """Check a persisted role; approval is recorded separately on the server."""
    try:
        normalized_role = UserRole(role)
    except ValueError:
        return False
    return permission in ROLE_PERMISSIONS[normalized_role]
