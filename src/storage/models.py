from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from parser.models import Article


@dataclass(slots=True, frozen=True)
class CacheSnapshot:
    """
    Represents one cache snapshot.
    """

    created_at: datetime
    articles: list[Article]
