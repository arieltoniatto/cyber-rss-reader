from datetime import datetime, timezone

import feedparser
import pytest

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


@pytest.mark.parametrize("path", ["rssfeed.xml", "rssfeed_full.xml"])
def test_sans_diary_feed_excludes_stormcast_announcements(path):
    feed = Feed(name="Renamed SANS source", url=f"https://isc.sans.edu/{path}", category="dfir")
    parsed = feedparser.parse(b'''<rss version="2.0"><channel><title>SANS</title>
      <item><title>ISC Stormcast For Tuesday, October 13th, 2026</title>
        <link>https://isc.sans.edu/diary/rss/33418</link></item>
      <item><title>SANS Stormcast Monday</title>
        <link>https://isc.sans.edu/diary/rss/33416</link></item>
      <item><title>Investigating malware mentioned in ISC Stormcast</title>
        <description>Technical diary content.</description>
        <link>https://isc.sans.edu/diary/rss/33414</link></item>
    </channel></rss>''')
    articles = RSSParser().parse([FeedResult(feed=feed, parsed=parsed)])
    assert len(articles) == 1
    assert articles[0].title == "Investigating malware mentioned in ISC Stormcast"
    assert articles[0].summary == "Technical diary content."
    assert articles[0].category == "dfir"


@pytest.mark.parametrize("url", [
    "https://isc.sans.edu/dailypodcast.xml",
    "https://example.com/rssfeed_full.xml",
])
def test_stormcast_is_preserved_in_podcast_and_other_feeds(url):
    feed = Feed(name="Podcast source", url=url, category="podcasts")
    parsed = feedparser.parse(b'''<rss version="2.0"><channel><title>Podcast</title>
      <item><title>SANS Stormcast Tuesday, October 13th, 2026</title>
        <link>https://isc.sans.edu/podcastdetail/10134</link>
        <description>Episode notes.</description></item>
    </channel></rss>''')
    articles = RSSParser().parse([FeedResult(feed=feed, parsed=parsed)])
    assert len(articles) == 1
    assert articles[0].url == "https://isc.sans.edu/podcastdetail/10134"
    assert articles[0].category == "podcasts"
    assert articles[0].summary == "Episode notes."
