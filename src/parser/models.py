from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True, frozen=True)
class Article:
    """
    Unified article model used throughout the application,
    regardless of the original RSS/Atom feed format.
    """

    title: str
    source: str
    summary: str
    url: str

    category: str | None = None
    author: str | None = None
    published: datetime | None = None

    tags: list[str] = field(default_factory=list)