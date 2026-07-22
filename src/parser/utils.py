from __future__ import annotations

from datetime import datetime, date
from email.utils import parsedate_to_datetime
from typing import Any


def parse_datetime(value: str | None) -> datetime | None:
    """
    Convert RSS date strings into datetime objects.

    Returns None when parsing fails.
    """

    if not value:
        return None

    try:
        return parsedate_to_datetime(value)
    except Exception:
        return None


def extract_tags(entry: Any) -> list[str]:
    """
    Extract category/tag labels from a feed entry.
    """

    tags: list[str] = []

    for tag in getattr(entry, "tags", []):
        term = getattr(tag, "term", None)

        if term:
            tags.append(str(term))

    return tags


def first_available(entry: Any, *fields: str) -> str | None:
    """
    Return the first non-empty field from an RSS entry.
    """

    for field in fields:
        value = getattr(entry, field, None)

        if value:
            return str(value)

    return None

def parse_published(entry) -> datetime | None:

    parsed = (
        entry.get("published_parsed")
        or entry.get("updated_parsed")
    )

    if parsed:
        return date(
            year=parsed.tm_year,
            month=parsed.tm_mon,
            day=parsed.tm_mday,
        )

    value = (
        entry.get("published")
        or entry.get("updated")
    )

    if value:
        try:
            return parsedate_to_datetime(
                value
            ).date()

        except Exception:
            return None

    return None