"""Shared UTC timestamp helpers for legacy naive-UTC database columns."""

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return the current UTC instant as a naive datetime for existing schemas.

    The database stores UTC timestamps without timezone metadata. Keeping this
    helper naive preserves existing comparisons and serialization while avoiding
    the deprecated ``datetime.utcnow()`` API.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)
