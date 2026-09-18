"""Transaction-local tenant GUCs.

RLS policies read two settings that we set with ``set_config(..., is_local=true)``
so they live only for the current transaction. This is essential with pooled
connections: transaction-local state cannot leak into a later request that
reuses the same physical connection.

- ``app.user_id``   set right after authentication (identity)
- ``app.tenant_id`` set only after membership is confirmed (active tenant)
"""

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def set_current_user(session: AsyncSession, user_id: uuid.UUID) -> None:
    await session.execute(
        text("SELECT set_config('app.user_id', :value, true)"),
        {"value": str(user_id)},
    )


async def set_current_tenant(session: AsyncSession, tenant_id: uuid.UUID) -> None:
    await session.execute(
        text("SELECT set_config('app.tenant_id', :value, true)"),
        {"value": str(tenant_id)},
    )
