from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from config.models import Feed
from feeds.models import FeedResult, FeedObservation
from feeds.fetcher import RSSFetcher
from config.models import FeedCategory, FeedConfiguration
from enrichment.pipeline import EnrichmentPipeline
from parser.models import Article
from parser.parser import RSSParser
from services.article_service import ArticleService
from services.models import LatestQuery
from storage.sqlite_storage import SQLiteArticleRepository
import feedparser


@pytest.mark.asyncio
async def test_partial_update_preserves_other_sources_and_counts_unique_articles(tmp_path):
    repository = SQLiteArticleRepository(tmp_path / "archive.sqlite3")
    repository.save([Article(title="Existing", source="Failed source", summary="", url="https://example.com/old")])
    xml = b'<rss version="2.0"><channel><title>Feed</title><item><title>New</title><link>https://example.com/new</link></item><item><title>New duplicate</title><link>https://example.com/new</link></item></channel></rss>'
    result = FeedResult(feed=Feed(name="Available source", url="https://example.com/feed"), parsed=feedparser.parse(xml))
    fetcher = AsyncMock()
    fetcher.fetch_all.return_value = [result]
    service = ArticleService(repository=repository, fetcher=fetcher, parser=RSSParser(),
                             enrichment_pipeline=EnrichmentPipeline())
    update = await service.update(force_refresh=True)
    assert update.articles_parsed == 2
    assert update.articles_saved == 1
    assert len(repository.load()) == 2
    fetcher.fetch_all.reset_mock()
    assert (await service.update()).cache_used
    fetcher.fetch_all.assert_not_called()


@pytest.mark.asyncio
async def test_latest_paginates_with_dates_missing(tmp_path):
    repo = SQLiteArticleRepository(tmp_path / "archive.sqlite3")
    repo.save([Article(title="Undated", source="Source", summary="", url="https://example.com/a"),
               Article(title="Dated", source="Source", summary="", url="https://example.com/b",
                       published=datetime(2026, 1, 1, tzinfo=timezone.utc))])
    service = ArticleService(repository=repo, fetcher=None, parser=RSSParser(),
                             enrichment_pipeline=EnrichmentPipeline())
    assert [a.title for a in await service.latest(LatestQuery(limit=1, offset=1))] == ["Undated"]


@pytest.mark.asyncio
async def test_failed_collection_does_not_refresh_archive(tmp_path):
    repo = SQLiteArticleRepository(tmp_path / "archive.sqlite3")
    repo.save([Article(title="Old", source="Source", summary="", url="https://example.com/old")])
    fetcher = AsyncMock()
    fetcher.fetch_all.return_value = []
    service = ArticleService(repository=repo, fetcher=fetcher, parser=RSSParser(),
                             enrichment_pipeline=EnrichmentPipeline())
    result = await service.update(force_refresh=True)
    assert result.articles_saved == 0
    assert len(repo.load()) == 1
    assert not repo.is_cache_valid()


@pytest.mark.asyncio
async def test_real_fetcher_records_failure_and_success_and_cache_hit_is_not_an_attempt(tmp_path):
    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    good = Feed(name='Good', url='https://example.com/good')
    bad = Feed(name='Bad', url='https://example.com/bad')
    config = FeedConfiguration(source_directory=tmp_path,
                               categories=[FeedCategory(category='news', feeds=[good, bad])])
    fetcher = RSSFetcher(config)

    async def download(url):
        if url.endswith('/bad'):
            raise ValueError('HTTP 404')
        return b'<rss version="2.0"><channel><title>Feed</title><item><title>Test</title><link>https://example.com/article</link></item></channel></rss>'

    fetcher.client.fetch = AsyncMock(side_effect=download)
    service = ArticleService(repository=repo, fetcher=fetcher, parser=RSSParser(),
                             enrichment_pipeline=EnrichmentPipeline())
    result = await service.update(force_refresh=True)
    assert result.feeds_downloaded == 1
    assert result.feeds_failed == 1
    states = {row['name']: row for row in repo.feed_status()}
    assert states['Good']['status'] == 'success'
    assert states['Good']['article_count'] == 1
    assert states['Bad']['last_success'] is None
    assert 'HTTP 404' in states['Bad']['last_error']
    assert (await service.update()).cache_used
    assert {row['name']: row for row in repo.feed_status()} == states


@pytest.mark.asyncio
async def test_parser_failure_isolated_and_persisted(tmp_path):
    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    feed = Feed(name='Bad', url='https://example.com/feed')
    fetcher = AsyncMock()
    fetcher.fetch_all.return_value = [FeedResult(feed=feed, parsed=feedparser.FeedParserDict(entries=[]))]

    class BrokenParser:
        def parse(self, feeds):
            raise ValueError('Invalid publication date')

    service = ArticleService(repository=repo, fetcher=fetcher, parser=BrokenParser(),
                             enrichment_pipeline=EnrichmentPipeline())
    result = await service.update(force_refresh=True)
    assert result.feeds_failed == 1
    assert 'Parser ValueError' in repo.feed_status()[0]['last_error']
    assert not repo.is_cache_valid()


@pytest.mark.asyncio
async def test_failed_article_commit_does_not_report_success(tmp_path):
    class FailingRepository(SQLiteArticleRepository):
        def save_collection(self, articles, observations):
            if articles:
                raise RuntimeError('Simulated write failure')
            super().save_collection(articles, observations)

    repo = FailingRepository(tmp_path / 'archive.sqlite3')
    feed = Feed(name='Source', url='https://example.com/feed')
    earlier = datetime(2026, 1, 1, tzinfo=timezone.utc)
    repo.save_collection([], [FeedObservation(feed=feed, attempted_at=earlier,
                                             completed_at=earlier, article_count=5)])
    fetcher = AsyncMock()
    parsed = feedparser.parse(b'<rss version="2.0"><channel><title>Feed</title><item><title>New</title></item></channel></rss>')
    fetcher.fetch_all.return_value = [FeedResult(feed=feed, parsed=parsed)]
    service = ArticleService(repository=repo, fetcher=fetcher, parser=RSSParser(),
                             enrichment_pipeline=EnrichmentPipeline())
    with pytest.raises(RuntimeError, match='write failure'):
        await service.update(force_refresh=True)
    state = repo.feed_status()[0]
    assert state['status'] == 'error'
    assert 'Processing RuntimeError' in state['last_error']
    assert state['last_success'] == earlier.isoformat()
    assert state['last_success_article_count'] == 5
    assert repo.load() == []


@pytest.mark.asyncio
async def test_unexpected_fetch_failure_marks_configured_feeds(tmp_path):
    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    feed = Feed(name='Source', url='https://example.com/feed')
    fetcher = AsyncMock()
    fetcher.configuration = FeedConfiguration(source_directory=tmp_path,
        categories=[FeedCategory(category='news', feeds=[feed])])
    fetcher.fetch_all.side_effect = RuntimeError('Collector failed')
    service = ArticleService(repository=repo, fetcher=fetcher, parser=RSSParser(),
                             enrichment_pipeline=EnrichmentPipeline())
    with pytest.raises(RuntimeError, match='Collector failed'):
        await service.update(force_refresh=True)
    state = repo.feed_status()[0]
    assert state['status'] == 'error'
    assert 'Collector failed' in state['last_error']
    assert state['last_success'] is None


@pytest.mark.asyncio
async def test_collection_reports_retention_removals(tmp_path):
    from storage.retention import RetentionPolicy
    repo = SQLiteArticleRepository(tmp_path/'archive.sqlite3', retention=RetentionPolicy(max_articles=1))
    repo.save([Article(title='Old', source='Source', summary='', url='https://example.com/old')])
    xml = b'<rss version="2.0"><channel><title>Feed</title><item><title>New</title><link>https://example.com/new</link></item></channel></rss>'
    fetcher = AsyncMock()
    fetcher.fetch_all.return_value = [FeedResult(feed=Feed(name='Source', url='https://example.com/feed'), parsed=feedparser.parse(xml))]
    service = ArticleService(repository=repo, fetcher=fetcher, parser=RSSParser(), enrichment_pipeline=EnrichmentPipeline())
    result = await service.update(force_refresh=True)
    assert result.articles_saved == 1 and result.articles_pruned == 1
    assert [a.title for a in repo.load()] == ['New']
