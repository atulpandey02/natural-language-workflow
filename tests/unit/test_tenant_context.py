"""Role privilege ordering."""

from nlw.tenancy.context import Role, role_at_least


def test_role_ordering() -> None:
    assert role_at_least(Role.OWNER, Role.MEMBER)
    assert role_at_least(Role.OWNER, Role.OWNER)
    assert role_at_least(Role.ADMIN, Role.MEMBER)
    assert not role_at_least(Role.MEMBER, Role.ADMIN)
    assert not role_at_least(Role.ADMIN, Role.OWNER)
