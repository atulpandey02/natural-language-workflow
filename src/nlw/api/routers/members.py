"""Membership & invitation endpoints (M11.5 P3A).

- ``GET    /members``                    roster of the active workspace (any member)
- ``PATCH  /members/{user_id}``          change a member's role (admin/owner)
- ``DELETE /members/{user_id}``          remove a member (admin/owner)
- ``GET    /invitations``                pending invitations (admin/owner)
- ``POST   /invitations``                create an invitation (admin/owner) -> raw token ONCE
- ``POST   /invitations/{id}/revoke``    revoke a pending invitation (admin/owner)
- ``POST   /invitations/accept``         accept an invitation (any authenticated user)

Authorization is fail-closed and DB-backed: RLS gates admin/owner writes, admins
cannot touch owner rows, and the owner-preservation trigger blocks removing/demoting
the final owner. Invitation tokens are single-use and stored only as a hash.
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.api.deps import get_app_settings, get_current_user, get_session, get_tenant_context
from nlw.api.schemas import (
    InvitationAccept,
    InvitationAcceptedOut,
    InvitationCreate,
    InvitationCreatedOut,
    InvitationOut,
    MemberOut,
    RoleUpdate,
)
from nlw.authz.invitations import hash_token, new_invitation_token, normalize_email
from nlw.core.config import Settings
from nlw.db.models import User
from nlw.db.repositories import AuditRepository, InvitationRepository, MembershipRepository
from nlw.tenancy.context import Role, TenantContext, role_at_least
from nlw.tenancy.session import set_current_tenant, set_current_user

router = APIRouter()
log = structlog.get_logger(__name__)


def _iso(value: object) -> str | None:
    return value.isoformat() if value is not None else None  # type: ignore[attr-defined]


def _sqlstate(exc: BaseException) -> str | None:
    orig = getattr(exc, "orig", None)
    return getattr(orig, "sqlstate", None) or getattr(exc, "sqlstate", None)


def _membership_error(exc: Exception, verb: str) -> HTTPException:
    """Map a ``manage_membership`` failure to a stable, non-enumerating HTTP error.
    42501 (denied: not admin/owner, owner-only row, or target absent) -> 403;
    23514 (final-owner invariant) -> 409. Anything else -> 409. No internals leak."""
    state = _sqlstate(exc)
    if state == "42501":
        return HTTPException(status.HTTP_403_FORBIDDEN, f"{verb} not allowed")
    return HTTPException(
        status.HTTP_409_CONFLICT, f"{verb} not allowed (workspace must keep an owner)"
    )


async def _admin_ctx(ctx: TenantContext = Depends(get_tenant_context)) -> TenantContext:
    if not role_at_least(ctx.role, Role.ADMIN):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
    return ctx


@router.get("/members", response_model=list[MemberOut])
async def list_members(
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> list[MemberOut]:
    rows = await MembershipRepository(session).list_for_workspace(ctx.tenant_id)
    return [MemberOut(user_id=m.user_id, role=m.role) for m in rows]


@router.patch("/members/{user_id}", response_model=MemberOut)
async def change_member_role(
    user_id: uuid.UUID,
    body: RoleUpdate,
    request: Request,
    ctx: TenantContext = Depends(_admin_ctx),
) -> MemberOut:
    if body.role not in ("owner", "admin", "member"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid role")
    sessionmaker = request.app.state.sessionmaker
    try:
        async with sessionmaker() as session, session.begin():
            await set_current_user(session, ctx.user_id)
            await set_current_tenant(session, ctx.tenant_id)
            # manage_membership authorizes, mutates, preserves >=1 owner, and audits
            # atomically. It RAISES on denial/final-owner; no separate emit here.
            await MembershipRepository(session).set_role(user_id, ctx.tenant_id, body.role)
    except Exception as exc:
        raise _membership_error(exc, "role change") from exc
    return MemberOut(user_id=user_id, role=body.role)


@router.delete("/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    user_id: uuid.UUID,
    request: Request,
    ctx: TenantContext = Depends(_admin_ctx),
) -> None:
    sessionmaker = request.app.state.sessionmaker
    try:
        async with sessionmaker() as session, session.begin():
            await set_current_user(session, ctx.user_id)
            await set_current_tenant(session, ctx.tenant_id)
            await MembershipRepository(session).remove(user_id, ctx.tenant_id)
    except Exception as exc:
        raise _membership_error(exc, "removal") from exc


@router.get("/invitations", response_model=list[InvitationOut])
async def list_invitations(
    ctx: TenantContext = Depends(_admin_ctx),
    session: AsyncSession = Depends(get_session),
) -> list[InvitationOut]:
    rows = await InvitationRepository(session).list_pending(ctx.tenant_id)
    return [
        InvitationOut(
            id=i.id,
            email=i.email,
            role=i.role,
            status=i.status,
            expires_at=_iso(i.expires_at),
            created_at=_iso(i.created_at),
        )
        for i in rows
    ]


@router.post(
    "/invitations", response_model=InvitationCreatedOut, status_code=status.HTTP_201_CREATED
)
async def create_invitation(
    body: InvitationCreate,
    request: Request,
    ctx: TenantContext = Depends(_admin_ctx),
    settings: Settings = Depends(get_app_settings),
) -> InvitationCreatedOut:
    if body.role not in ("admin", "member"):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "invitations may grant admin/member"
        )
    email = normalize_email(body.email)
    if not email or "@" not in email:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "a valid email is required")
    raw_token, token_hash = new_invitation_token()
    sessionmaker = request.app.state.sessionmaker
    async with sessionmaker() as session, session.begin():
        await set_current_user(session, ctx.user_id)
        await set_current_tenant(session, ctx.tenant_id)
        repo = InvitationRepository(session)
        if await repo.count_pending(ctx.tenant_id) >= settings.invitation_max_pending_per_workspace:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "too many pending invitations for this workspace"
            )
        inv = await repo.create(
            tenant_id=ctx.tenant_id,
            email=email,
            role=body.role,
            invited_by=ctx.user_id,
            token_hash=token_hash,
            expiry_hours=settings.invitation_expiry_hours,
        )
        if inv is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "a pending invitation for this email already exists"
            )
        await AuditRepository(session).emit(
            tenant_id=ctx.tenant_id,
            event_type="invitation.created",
            actor_user_id=ctx.user_id,
            subject_id=inv.id,
            detail=body.role,
        )
        out = InvitationCreatedOut(
            id=inv.id,
            email=inv.email,
            role=inv.role,
            status=inv.status,
            expires_at=_iso(inv.expires_at),
            created_at=_iso(inv.created_at),
            token=raw_token,
        )
    # The raw token is returned ONCE here and never logged/stored/returned again.
    log.info("invitation.created", tenant_id=str(ctx.tenant_id), invitation_id=str(out.id))
    return out


@router.post("/invitations/{invitation_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_invitation(
    invitation_id: uuid.UUID,
    request: Request,
    ctx: TenantContext = Depends(_admin_ctx),
) -> None:
    sessionmaker = request.app.state.sessionmaker
    async with sessionmaker() as session, session.begin():
        await set_current_user(session, ctx.user_id)
        await set_current_tenant(session, ctx.tenant_id)
        ok = await InvitationRepository(session).revoke(invitation_id, ctx.tenant_id)
        if not ok:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no pending invitation to revoke")
        await AuditRepository(session).emit(
            tenant_id=ctx.tenant_id,
            event_type="invitation.revoked",
            actor_user_id=ctx.user_id,
            subject_id=invitation_id,
        )


@router.post("/invitations/accept", response_model=InvitationAcceptedOut)
async def accept_invitation(
    body: InvitationAccept,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> InvitationAcceptedOut:
    # Use the REQUEST session: get_current_user provisioned this user (and set
    # app.user_id) in THIS uncommitted transaction, so the atomic accept function
    # must run here to see the just-created identity + verified email.
    from nlw.authz.invitations import MAX_TOKEN_LENGTH

    if not body.token or len(body.token) > MAX_TOKEN_LENGTH:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invitation is not valid")
    token_hash = hash_token(body.token)
    try:
        workspace_id = await InvitationRepository(session).accept(token_hash)
        membership = await MembershipRepository(session).get(user.id, workspace_id)
    except Exception as exc:  # uniform sanitized failure — no enumeration
        log.info("invitation.accept_failed", error_class=type(exc).__name__)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invitation is not valid") from exc
    role = membership.role if membership is not None else "member"
    log.info("invitation.accepted", workspace_id=str(workspace_id), user_id=str(user.id))
    return InvitationAcceptedOut(workspace_id=workspace_id, role=role)
