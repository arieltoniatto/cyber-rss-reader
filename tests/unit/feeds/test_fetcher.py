import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

from config.models import Feed, FeedCategory, FeedConfiguration
from feeds.fetcher import RSSFetcher


def test_repeated_cycles_respect_concurrency_across_event_loops():
    configuration = FeedConfiguration(source_directory=Path("."), categories=[
        FeedCategory(category="news", feeds=[Feed(name=f"Feed {i}", url=f"https://example.com/{i}")
                                             for i in range(5)])])
    fetcher = RSSFetcher(configuration, concurrency=2)
    active, maximum = 0, 0

    async def fetch(url):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        await asyncio.sleep(0.001)
        active -= 1
        if url.endswith("/4"):
            raise ValueError("Unavailable feed")
        return b'<rss version="2.0"><channel><title>Test</title></channel></rss>'

    fetcher.client.fetch = AsyncMock(side_effect=fetch)
    results = asyncio.run(fetcher.fetch_all())
    assert len(results) == 5
    assert sum(result.error is None for result in results) == 4
    assert results[-1].feed.name == "Feed 4"
    assert "Unavailable feed" in results[-1].error
    results = asyncio.run(fetcher.fetch_all())
    assert len(results) == 5
    assert sum(result.error is None for result in results) == 4
    assert results[-1].feed.name == "Feed 4"
    assert "Unavailable feed" in results[-1].error
    assert maximum == 2


def test_html_response_is_a_failure_even_with_http_success():
    config = FeedConfiguration(source_directory=Path('.'), categories=[
        FeedCategory(category='news', feeds=[Feed(name='HTML', url='https://example.com/feed')])])
    fetcher = RSSFetcher(config)
    fetcher.client.fetch = AsyncMock(return_value=b'<html><body>Temporarily unavailable</body></html>')
    result = asyncio.run(fetcher.fetch_all())[0]
    assert result.error is not None
    assert 'not an RSS/Atom feed' in result.error


def test_empty_response_is_reported_and_next_collection_recovers():
    config = FeedConfiguration(source_directory=Path('.'), categories=[
        FeedCategory(category='news', feeds=[Feed(name='Check Point Research', url='https://research.checkpoint.com/feed/')])])
    fetcher = RSSFetcher(config)
    fetcher.client.fetch = AsyncMock(side_effect=[b'', b' \r\n\t',
        b'<rss version="2.0"><channel><title>Research</title><item><title>Report</title></item></channel></rss>'])
    for _ in range(2):
        result = asyncio.run(fetcher.fetch_all())[0]
        assert result.error == 'ValueError: Empty response from feed server'
        assert result.parsed.entries == []
    recovered = asyncio.run(fetcher.fetch_all())[0]
    assert recovered.error is None and len(recovered.parsed.entries) == 1


def test_parser_result_without_version_is_not_an_attribute_error(monkeypatch):
    import feedparser
    config = FeedConfiguration(source_directory=Path('.'), categories=[
        FeedCategory(category='news', feeds=[Feed(name='Source', url='https://example.com/feed')])])
    fetcher = RSSFetcher(config)
    fetcher.client.fetch = AsyncMock(return_value=b'Unexpected response')
    monkeypatch.setattr('feeds.fetcher.feedparser.parse', lambda xml: feedparser.FeedParserDict(entries=[], feed={}, bozo=False))
    result = asyncio.run(fetcher.fetch_all())[0]
    assert result.error == 'ValueError: Response is not an RSS/Atom feed'
