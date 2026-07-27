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