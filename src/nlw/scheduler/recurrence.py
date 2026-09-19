"""Deterministic, DST-aware recurrence math for the scheduler (M8, ADR-015).

Pure functions over a small structured recurrence model (no cron). Wall-clock
semantics in the schedule's IANA timezone via ``zoneinfo``:

- Spring-forward gap (a nonexistent local time): ``fold=0`` interprets the wall
  time with the pre-gap offset, which converts to the instant shifted forward by
  the gap duration — i.e., we fire just after the gap (the day is not skipped).
- Fall-back ambiguity (a repeated local time): ``fold=0`` selects the earlier
  occurrence, so we fire once.

No LLM input reaches this module; the API validates all fields.
"""

import enum
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# Bound the forward/backward search so a mis-specified recurrence can never loop.
_MAX_DAYS = 400
_MAX_HOURS = 48


class Frequency(enum.StrEnum):
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"


class RecurrenceError(ValueError):
    """Invalid recurrence specification."""


@dataclass(frozen=True)
class Recurrence:
    timezone: str  # IANA name
    frequency: Frequency
    minute: int
    hour: int | None = None  # required for daily/weekly
    day_of_week: int | None = None  # 0=Mon (ISO), required for weekly

    def __post_init__(self) -> None:
        try:
            ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
            raise RecurrenceError(f"invalid timezone: {self.timezone}") from exc
        if not 0 <= self.minute <= 59:
            raise RecurrenceError("minute must be 0..59")
        if self.frequency in (Frequency.DAILY, Frequency.WEEKLY) and (
            self.hour is None or not 0 <= self.hour <= 23
        ):
            raise RecurrenceError("hour (0..23) is required for daily/weekly")
        if self.frequency is Frequency.WEEKLY and (
            self.day_of_week is None or not 0 <= self.day_of_week <= 6
        ):
            raise RecurrenceError("day_of_week (0..6) is required for weekly")

    @property
    def _tz(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)


def _to_utc(naive_local: datetime, tz: ZoneInfo) -> datetime:
    """Localize a naive wall-clock time and return the UTC instant.

    ``fold=0`` gives the gap-shifted instant for nonexistent times and the
    earlier instant for ambiguous times (see module docstring)."""
    return naive_local.replace(tzinfo=tz, fold=0).astimezone(UTC)


def _daily_candidate(d: date, rec: Recurrence) -> datetime:
    assert rec.hour is not None
    return datetime.combine(d, time(rec.hour, rec.minute))


def next_occurrence(rec: Recurrence, after: datetime) -> datetime:
    """First occurrence strictly after ``after`` (aware), returned in UTC."""
    tz = rec._tz
    local_after = after.astimezone(tz)

    if rec.frequency is Frequency.HOURLY:
        base = local_after.replace(minute=rec.minute, second=0, microsecond=0, tzinfo=None)
        for i in range(_MAX_HOURS + 2):
            cand = base + timedelta(hours=i)
            utc = _to_utc(cand, tz)
            if utc > after:
                return utc
        raise RecurrenceError("no hourly occurrence found")

    start = local_after.date()
    for k in range(_MAX_DAYS):
        d = start + timedelta(days=k)
        if rec.frequency is Frequency.WEEKLY and d.weekday() != rec.day_of_week:
            continue
        utc = _to_utc(_daily_candidate(d, rec), tz)
        if utc > after:
            return utc
    raise RecurrenceError("no occurrence found within search bound")


def latest_occurrence(rec: Recurrence, at: datetime) -> datetime | None:
    """Most recent occurrence at or before ``at`` (aware), returned in UTC."""
    tz = rec._tz
    local_at = at.astimezone(tz)

    if rec.frequency is Frequency.HOURLY:
        base = local_at.replace(minute=rec.minute, second=0, microsecond=0, tzinfo=None)
        for i in range(_MAX_HOURS + 2):
            cand = base - timedelta(hours=i)
            utc = _to_utc(cand, tz)
            if utc <= at:
                return utc
        return None

    start = local_at.date()
    for k in range(_MAX_DAYS):
        d = start - timedelta(days=k)
        if rec.frequency is Frequency.WEEKLY and d.weekday() != rec.day_of_week:
            continue
        utc = _to_utc(_daily_candidate(d, rec), tz)
        if utc <= at:
            return utc
    return None
