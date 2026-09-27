"""Versioned, immutable public fixtures. Loading is pure and idempotent.

The fixed as-of date makes 'last six months' reproducible, never wall-clock
relative. No customer database, filesystem writes or secret is involved.
"""

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache
from random import Random

AS_OF = date(2026, 9, 1)
SEED = 1203
MONTHS = tuple(f"2026-{m:02d}" for m in range(1, 9))
CATEGORIES = ("Accessories", "Electronics", "Home", "Office")
REGIONS = ("East", "North", "South", "West")
TEAMS = ("Core", "Growth", "Specialists")
ISSUES = ("Billing", "Delivery", "Login", "Product")


@dataclass(frozen=True)
class Sale:
    order_date: date
    order_id: str
    customer_id: str
    product: str
    category: str
    region: str
    channel: str
    units: int
    unit_price_cents: int
    discount_percent: int
    revenue_cents: int


@dataclass(frozen=True)
class Ticket:
    ticket_id: str
    created_at: datetime
    resolved_at: datetime | None
    team: str
    issue_category: str
    priority: str
    status: str
    sla_target_hours: int
    resolution_hours: float | None
    reopened: bool
    csat: int | None


@lru_cache(maxsize=1)
def load_sales_v1() -> tuple[Sale, ...]:
    rng = Random(SEED)
    records: list[Sale] = []
    for month in range(1, 9):
        for category_index, category in enumerate(CATEGORIES):
            # Accessories has a deliberate sustained volume decline after May.
            count = (50 - (month - 5) * 10) if category_index == 0 and month > 5 else 45 + month * 2
            for i in range(count):
                units = rng.randint(1, 5)
                price = (2400, 16000, 6400, 3900)[category_index]
                discount = rng.choice((0, 0, 5, 10, 15))
                # Two deliberately conspicuous wholesale orders, documented.
                if month in (4, 7) and category_index == 1 and i == 0:
                    units = 45
                records.append(
                    Sale(
                        order_date=date(2026, month, 1 + i % 28),
                        order_id=f"SYN-O-{len(records) + 1:05d}",
                        customer_id=f"SYN-C-{rng.randint(1, 240):04d}",
                        product=("Everyday", "Premium")[i % 2] + " " + category,
                        category=category,
                        region=REGIONS[rng.randrange(4)],
                        channel=rng.choice(("Online", "Retail", "Partner")),
                        units=units,
                        unit_price_cents=price,
                        discount_percent=discount,
                        revenue_cents=units * price * (100 - discount) // 100,
                    )
                )
    return tuple(sorted(records, key=lambda r: (r.order_date, r.order_id)))


@lru_cache(maxsize=1)
def load_support_v1() -> tuple[Ticket, ...]:
    rng = Random(SEED + 1)
    records: list[Ticket] = []
    for month in range(1, 9):
        for i in range(135 + month * 5):
            team = TEAMS[i % 3]
            priority = ("High", "Normal", "Low")[i % 3]
            target = (8, 24, 48)[i % 3]
            created = datetime(2026, month, 1 + i % 28, i % 24, tzinfo=UTC)
            duration = round(rng.uniform(2, 36) + (month * 2 if team == "Growth" else 0), 2)
            if month == 7 and i in (1, 16):
                duration = 180.0
            open_ticket = month == 8 and i % 7 == 0
            resolved = None if open_ticket else created + timedelta(hours=duration)
            csat = None if open_ticket or i % 5 == 0 else max(1, min(5, 5 - int(duration / 18)))
            records.append(
                Ticket(
                    ticket_id=f"SYN-T-{len(records) + 1:05d}",
                    created_at=created,
                    resolved_at=resolved,
                    team=team,
                    issue_category=ISSUES[rng.choice((0, 0, 1, 2, 3))],
                    priority=priority,
                    status="Open" if open_ticket else "Resolved",
                    sla_target_hours=target,
                    resolution_hours=None if open_ticket else duration,
                    reopened=i % 13 == 0,
                    csat=csat,
                )
            )
    return tuple(sorted(records, key=lambda r: (r.created_at, r.ticket_id)))
