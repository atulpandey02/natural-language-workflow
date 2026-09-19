"""Deterministic, DST-aware recurrence math (M8)."""

from datetime import UTC, datetime

import pytest

from nlw.scheduler.recurrence import (
    Frequency,
    Recurrence,
    RecurrenceError,
    latest_occurrence,
    next_occurrence,
)

NY = "America/New_York"


def _utc(y: int, mo: int, d: int, h: int, mi: int) -> datetime:
    return datetime(y, mo, d, h, mi, tzinfo=UTC)


# --- Validation ---


def test_invalid_timezone() -> None:
    with pytest.raises(RecurrenceError):
        Recurrence(timezone="Mars/Phobos", frequency=Frequency.DAILY, minute=0, hour=9)


def test_daily_requires_hour() -> None:
    with pytest.raises(RecurrenceError):
        Recurrence(timezone="UTC", frequency=Frequency.DAILY, minute=0)


def test_weekly_requires_day_of_week() -> None:
    with pytest.raises(RecurrenceError):
        Recurrence(timezone="UTC", frequency=Frequency.WEEKLY, minute=0, hour=9)


# --- Normal daily (winter EST vs summer EDT) ---


def test_daily_est_winter() -> None:
    rec = Recurrence(timezone=NY, frequency=Frequency.DAILY, minute=0, hour=9)
    # 2026-01-15 07:00 EST (12:00 UTC) -> next 09:00 EST = 14:00 UTC.
    assert next_occurrence(rec, _utc(2026, 1, 15, 12, 0)) == _utc(2026, 1, 15, 14, 0)


def test_daily_edt_summer() -> None:
    rec = Recurrence(timezone=NY, frequency=Frequency.DAILY, minute=0, hour=9)
    # 2026-07-15 07:00 EDT (11:00 UTC) -> next 09:00 EDT = 13:00 UTC.
    assert next_occurrence(rec, _utc(2026, 7, 15, 11, 0)) == _utc(2026, 7, 15, 13, 0)


def test_daily_strictly_after() -> None:
    rec = Recurrence(timezone=NY, frequency=Frequency.DAILY, minute=0, hour=9)
    # Exactly at the occurrence -> returns the NEXT day, not the same instant.
    on_time = _utc(2026, 1, 15, 14, 0)
    assert next_occurrence(rec, on_time) == _utc(2026, 1, 16, 14, 0)


# --- DST: spring-forward gap (req 9: shift forward by the gap) ---


def test_spring_forward_nonexistent_shifts_by_gap() -> None:
    # 2026-03-08: 02:00 EST -> 03:00 EDT. A daily 02:30 is nonexistent that day.
    rec = Recurrence(timezone=NY, frequency=Frequency.DAILY, minute=30, hour=2)
    # after = 01:00 EST (06:00 UTC), before the transition.
    got = next_occurrence(rec, _utc(2026, 3, 8, 6, 0))
    # 02:30 shifted forward by the 1h gap -> 03:30 EDT = 07:30 UTC.
    assert got == _utc(2026, 3, 8, 7, 30)


# --- DST: fall-back ambiguity (fold=0 earlier) ---


def test_fall_back_ambiguous_fires_earlier() -> None:
    # 2026-11-01: 02:00 EDT -> 01:00 EST. A daily 01:30 occurs twice.
    rec = Recurrence(timezone=NY, frequency=Frequency.DAILY, minute=30, hour=1)
    # after = 00:00 EDT (04:00 UTC).
    got = next_occurrence(rec, _utc(2026, 11, 1, 4, 0))
    # Earlier occurrence (EDT -04:00): 01:30 EDT = 05:30 UTC (not 06:30 EST).
    assert got == _utc(2026, 11, 1, 5, 30)


# --- Weekly / hourly ---


def test_weekly_next_matches_day_of_week() -> None:
    # 0=Mon. 2026-01-15 is a Thursday (weekday 3).
    rec = Recurrence(timezone=NY, frequency=Frequency.WEEKLY, minute=0, hour=9, day_of_week=0)
    got = next_occurrence(rec, _utc(2026, 1, 15, 12, 0))
    # Next Monday is 2026-01-19; 09:00 EST = 14:00 UTC.
    assert got == _utc(2026, 1, 19, 14, 0)


def test_hourly_next_at_minute() -> None:
    rec = Recurrence(timezone="UTC", frequency=Frequency.HOURLY, minute=15)
    assert next_occurrence(rec, _utc(2026, 1, 1, 10, 20)) == _utc(2026, 1, 1, 11, 15)
    assert next_occurrence(rec, _utc(2026, 1, 1, 10, 10)) == _utc(2026, 1, 1, 10, 15)


# --- latest_occurrence (catch-up) ---


def test_latest_occurrence_daily() -> None:
    rec = Recurrence(timezone=NY, frequency=Frequency.DAILY, minute=0, hour=9)
    # at 15:00 EST (20:00 UTC) -> latest is today 09:00 EST = 14:00 UTC.
    assert latest_occurrence(rec, _utc(2026, 1, 15, 20, 0)) == _utc(2026, 1, 15, 14, 0)


def test_latest_occurrence_before_todays_is_yesterday() -> None:
    rec = Recurrence(timezone=NY, frequency=Frequency.DAILY, minute=0, hour=9)
    # at 08:00 EST (13:00 UTC), before today's 09:00 -> yesterday 09:00 = 14:00 UTC prev day.
    assert latest_occurrence(rec, _utc(2026, 1, 15, 13, 0)) == _utc(2026, 1, 14, 14, 0)
