"""SQLAlchemy declarative base. Models (from M2 onward) inherit from ``Base``."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base carrying the shared metadata for all ORM models."""
