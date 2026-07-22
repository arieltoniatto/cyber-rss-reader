from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date


@dataclass(slots=True, frozen=True)
class Article:
    """
    Unified article model used throughout the application,
    regardless of the original RSS/Atom feed format.
    """

    title: str
    source: str
    category: str

    author: str | None
    published: date | None

    summary: str | None

    url: str

    tags: list[str] = field(default_factory=list)