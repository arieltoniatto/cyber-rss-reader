from dataclasses import dataclass

import feedparser

from config.models import Feed


@dataclass(slots=True, frozen=True)
class FeedResult:
    """
    Result of downloading and parsing a single feed.
    """

    feed: Feed
    parsed: feedparser.FeedParserDict