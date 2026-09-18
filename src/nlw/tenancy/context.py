"""Tenant context: the authoritative (user, tenant, role) for a request.

Resolved from our own ``memberships`` table — never from a token claim or the
``X-Workspace-Id`` header (which is only a requested selector). ``tenant_id``
propagates from here into the execution context in later milestones.
"""

import enum
import uuid
from dataclasses import dataclass


class Role(enum.StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


_RANK: dict[Role, int] = {Role.MEMBER: 0, Role.ADMIN: 1, Role.OWNER: 2}


def role_at_least(role: Role, minimum: Role) -> bool:
    """True if ``role`` meets or exceeds ``minimum`` in the privilege order."""
    return _RANK[role] >= _RANK[minimum]


@dataclass(frozen=True)
class TenantContext:
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    role: Role
