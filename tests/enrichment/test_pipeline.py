from __future__ import annotations

from dataclasses import replace

import pytest

from enrichment.pipeline import EnrichmentPipeline
from parser.models import Article


class FirstTestEnricher:
    @property
    def name(self) -> str:
        return "first-test-enricher"

    async def enrich(self, article: Article) -> Article:
        return replace(
            article,
            tags=[*article.tags, "first"],
        )


class SecondTestEnricher:
    @property
    def name(self) -> str:
        return "second-test-enricher"

    async def enrich(self, article: Article) -> Article:
        return replace(
            article,
            tags=[*article.tags, "second"],
        )


class FailingTestEnricher:
    @property
    def name(self) -> str:
        return "failing-test-enricher"

    async def enrich(self, article: Article) -> Article:
        raise RuntimeError("Simulated enrichment failure")


@pytest.fixture
def article() -> Article:
    return Article(
        title="Test article",
        source="Test Source",
        summary="Test summary",
        url="https://example.com/article",
        category="news",
        author=None,
        published=None,
        tags=[],
    )


@pytest.mark.asyncio
async def test_pipeline_runs_enrichers_in_order(
    article: Article,
) -> None:
    pipeline = EnrichmentPipeline(
        enrichers=[
            FirstTestEnricher(),
            SecondTestEnricher(),
        ]
    )

    result = await pipeline.enrich(article)

    assert result.tags == [
        "first",
        "second",
    ]


@pytest.mark.asyncio
async def test_pipeline_continues_after_failure(
    article: Article,
) -> None:
    pipeline = EnrichmentPipeline(
        enrichers=[
            FirstTestEnricher(),
            FailingTestEnricher(),
            SecondTestEnricher(),
        ],
        continue_on_error=True,
    )

    result = await pipeline.enrich(article)

    assert result.tags == [
        "first",
        "second",
    ]


@pytest.mark.asyncio
async def test_pipeline_raises_when_continue_on_error_is_false(
    article: Article,
) -> None:
    pipeline = EnrichmentPipeline(
        enrichers=[
            FailingTestEnricher(),
        ],
        continue_on_error=False,
    )

    with pytest.raises(
        RuntimeError,
        match="Simulated enrichment failure",
    ):
        await pipeline.enrich(article)


@pytest.mark.asyncio
async def test_pipeline_enriches_multiple_articles(
    article: Article,
) -> None:
    pipeline = EnrichmentPipeline(
        enrichers=[
            FirstTestEnricher(),
        ]
    )

    second_article = replace(
        article,
        title="Second article",
        url="https://example.com/second",
    )

    results = await pipeline.enrich_many(
        [
            article,
            second_article,
        ]
    )

    assert len(results) == 2
    assert results[0].tags == ["first"]
    assert results[1].tags == ["first"]

@pytest.mark.asyncio
async def test_collection_persists_validated_iocs_and_contextual_malware(tmp_path):
    import json
    import feedparser
    from unittest.mock import AsyncMock

    from config.models import Feed
    from feeds.models import FeedResult
    from enrichment.ioc_enricher import IOCEnricher
    from enrichment.malware_enricher import MalwareEnricher
    from parser.models import IOC, IOCType
    from parser.parser import RSSParser
    from services.article_service import ArticleService
    from storage.sqlite_storage import SQLiteArticleRepository

    catalog = tmp_path / 'malware.json'
    catalog.write_text(json.dumps({'malware': [{'name': 'BlackEnergy'}, {'name': 'Milan'}]}))
    xml = b'''<rss version="2.0"><channel><title>Reports</title>
      <item><title>BlackEnergy activity</title><link>https://publisher.test/positive</link>
      <description>Payload from hxxps://EVIL[.]test/Case. CVE-2026-1234 AS4294967296 999.1.2.3</description></item>
      <item><title>Meeting in Milan</title><link>https://publisher.test/negative</link>
      <description>Page with links: https://blackenergy.test/tools/sample.exe/path.fake</description></item>
    </channel></rss>'''
    fetcher = AsyncMock()
    fetcher.fetch_all.return_value = [FeedResult(feed=Feed(name='Source', url='https://publisher.test/rss'),
                                                parsed=feedparser.parse(xml))]
    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    pipeline = EnrichmentPipeline([IOCEnricher(), MalwareEnricher(catalog)], continue_on_error=False)
    service = ArticleService(repository=repo, fetcher=fetcher, parser=RSSParser(), enrichment_pipeline=pipeline)
    result = await service.update(force_refresh=True)
    assert result.articles_saved == 2
    saved = {a.title: a for a in repo.load()}
    positive = saved['BlackEnergy activity']
    assert positive.malware == ['BlackEnergy']
    assert IOC(IOCType.URL, 'https://evil.test/Case') in positive.iocs
    assert IOC(IOCType.CVE, 'CVE-2026-1234') in positive.iocs
    assert not any(ioc.type in (IOCType.ASN, IOCType.IPV4) for ioc in positive.iocs)
    negative = saved['Meeting in Milan']
    assert negative.malware == []
    assert {ioc.value for ioc in negative.iocs if ioc.type == IOCType.DOMAIN} == {'blackenergy.test'}
