from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import html
from typing import Any
from bs4 import BeautifulSoup
from parser.dates import normalize_datetime


def clean_html(text: str) -> str:
    """
    Decode HTML entities and remove HTML tags when present.
    """

    text = html.unescape(text)

    # Only invoke BeautifulSoup if the text actually looks like HTML.
    if "<" in text and ">" in text:
        return BeautifulSoup(
            text,
            "html.parser",
        ).get_text(
            " ",
            strip=True,
        )

    return text.strip()


def parse_datetime(value: str | None) -> datetime | None:
    """
    Convert RSS date strings into datetime objects.

    Returns None when parsing fails.
    """

    if not value:
        return None

    try:
        return normalize_datetime(parsedate_to_datetime(value))
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
    for field in fields:
        value = getattr(entry, field, None)

        if value:
            return clean_html(str(value))

    return None


def parse_published(entry) -> datetime | None:

    parsed = (
        entry.get("published_parsed")
        or entry.get("updated_parsed")
    )

    if parsed:
        return datetime(
            year=parsed.tm_year,
            month=parsed.tm_mon,
            day=parsed.tm_mday,
            hour=parsed.tm_hour,
            minute=parsed.tm_min,
            second=parsed.tm_sec,
            tzinfo=timezone.utc,
        )

    value = (
        entry.get("published")
        or entry.get("updated")
    )

    if value:
        try:
            return normalize_datetime(parsedate_to_datetime(value))

        except Exception:
            return None

    return None

def parse_tags(entry: Any) -> list[str]:
    """
    Extract tags/categories from a feedparser entry.

    Supports FeedParserDict and regular dictionaries.
    """

    tags: list[str] = []

    raw_tags = getattr(entry, "tags", None)

    if raw_tags is None and hasattr(entry, "get"):
        raw_tags = entry.get("tags", [])

    for tag in raw_tags or []:
        term = None

        if hasattr(tag, "get"):
            term = tag.get("term")

        if term is None:
            term = getattr(tag, "term", None)

        if term:
            cleaned = str(term).strip()

            if cleaned:
                tags.append(cleaned)

    return list(dict.fromkeys(tags))