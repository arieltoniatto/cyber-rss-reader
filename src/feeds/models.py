from dataclasses import dataclass, field

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