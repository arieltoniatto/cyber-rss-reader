from dataclasses import dataclass, field
from datetime import datetime, timezone

import feedparser

from config.models import Feed


@dataclass(slots=True, frozen=True)
class FeedResult:
    """
    Result of downloading and parsing a single feed.
    """

    feed: Feed
    parsed: feedparser.FeedParserDict
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    attempted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True, frozen=True)
class FeedObservation:
    feed: Feed
    attempted_at: datetime
    completed_at: datetime
    article_count: int = 0
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
