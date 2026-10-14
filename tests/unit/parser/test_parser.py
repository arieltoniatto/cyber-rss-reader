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


@pytest.mark.parametrize('format', ['rss', 'atom-html', 'atom-xhtml'])
def test_embedded_content_is_used_without_truncation(format):
    body = 'Detailed research and CVE-2026-1234 evidence. ' * 30 + 'Final paragraph.'
    if format == 'rss':
        xml = f'''<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
          <channel><title>Research</title><item><title>Report</title>
          <link>https://example.com/report</link><description>Short preview.</description>
          <content:encoded><![CDATA[<p>{body}</p>]]></content:encoded>
          </item></channel></rss>'''
    elif format == 'atom-html':
        xml = f'''<feed xmlns="http://www.w3.org/2005/Atom"><title>Research</title>
          <entry><title>Report</title><id>https://example.com/report</id>
          <link href="https://example.com/report"/><summary>Short preview.</summary>
          <content type="html"><![CDATA[<p>{body}</p>]]></content></entry></feed>'''
    else:
        xml = f'''<feed xmlns="http://www.w3.org/2005/Atom"><title>Research</title>
          <entry><title>Report</title><id>https://example.com/report</id>
          <summary>Short preview.</summary><content type="xhtml">
          <div xmlns="http://www.w3.org/1999/xhtml"><p>{body}</p></div>
          </content></entry></feed>'''
    parsed = feedparser.parse(xml.encode())
    feed = Feed(name='Research', url='https://example.com/feed')
    article = RSSParser().parse([FeedResult(feed=feed, parsed=parsed)])[0]
    assert article.summary == body
    assert len(article.summary) > 600


@pytest.mark.parametrize('content', [None, 'invalid', [{}], [None],
    [{'value': 42}], [{'value': '<p> </p>', 'type': 'text/html'}],
    [{'value': 'x'*1000, 'type': 'image/png'}],
    [{'src': 'https://example.com/full-text', 'type': 'text/html'}]])
def test_unusable_or_external_content_keeps_summary(content):
    from parser.utils import article_text
    entry = feedparser.FeedParserDict(summary='Existing summary.', content=content)
    assert article_text(entry) == 'Existing summary.'


def test_longest_readable_variant_keeps_summary_if_content_is_shorter():
    from parser.utils import article_text
    entry = feedparser.FeedParserDict(summary='A longer summary with more useful information.', content=[
        {'value': '<p>Short.</p>', 'type': 'text/html'},
        {'value': 'Alternative.', 'type': 'text/plain'},
    ])
    assert article_text(entry) == entry.summary
    entry.content.append({'value': 'Extended article &amp; evidence. '*10, 'type': 'text/plain'})
    assert article_text(entry) == ('Extended article & evidence. '*10).strip()


def test_content_only_feed_preserves_readable_text_and_ignores_markup():
    from parser.utils import article_text
    entry = feedparser.FeedParserDict(content=[
        {'type': 'text/html', 'value': '<p>Report &amp; evidence.</p><script>alert(1)</script><p>Second paragraph.</p>'},
        {'type': 'text/plain', 'value': 'Short version.'},
    ])
    assert article_text(entry) == 'Report & evidence. Second paragraph.'
