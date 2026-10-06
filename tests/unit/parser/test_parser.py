from datetime import datetime, timezone

import feedparser

from config.models import Feed
from feeds.models import FeedResult
from parser.parser import RSSParser
from parser.utils import parse_published


def test_fallback_date_is_utc_datetime():
    assert parse_published({"published": "Fri, 02 Oct 2026 12:00:00 GMT"}) == datetime(2026, 10, 2, 12, tzinfo=timezone.utc)
    assert parse_published({"published": "invalid"}) is None


def test_missing_summary_and_date_are_supported():
    feed = Feed(name="Source", url="https://example.com/feed", category="news")
    parsed = feedparser.parse(b'<rss version="2.0"><channel><title>Feed</title><item><title>Article</title></item></channel></rss>')
    article = RSSParser().parse([FeedResult(feed=feed, parsed=parsed)])[0]
    assert article.summary == ""
    assert article.published is None
