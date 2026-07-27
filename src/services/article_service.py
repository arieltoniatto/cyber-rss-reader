from __future__ import annotations

import logging
from datetime import datetime

from feeds.fetcher import RSSFetcher
from parser.models import Article
from parser.parser import RSSParser
from storage.interfaces import ArticleRepository
from services.exceptions import InvalidCategoryError, InvalidSourceError
from services.models import LatestQuery, UpdateResult
from enrichment.pipeline import EnrichmentPipeline


logger = logging.getLogger(__name__)


class ArticleService:
    """
    Coordinates fetching, parsing and persistence.

    This class contains application logic only.
    """

    def __init__(
        self,
        *,
        repository: ArticleRepository,
        fetcher: RSSFetcher,
        parser: RSSParser,
        enrichment_pipeline: EnrichmentPipeline,
    ) -> None:

        self._repository = repository
        self._fetcher = fetcher
        self._parser = parser
        self._enrichment_pipeline = enrichment_pipeline

    def _available_categories(
            self,
            articles: list[Article],
        ) -> list[str]:

        return sorted(
            {
                article.category
                for article in articles
                if article.category
            }
        )

    def _available_sources(
            self,
            articles: list[Article],
        ) -> list[str]:

        return sorted(
            {
                article.source
                for article in articles
                if article.source
            }
        )

    def _validate_category(
        self,
        category: str,
        articles: list[Article],
    ) -> None:
        available = self._available_categories(articles)

        if category not in available:
            raise InvalidCategoryError(
                f"Unknown category: {category}.\n"
                f"Available categories: {', '.join(available)}"
            )


    def _validate_source(
        self,
        source: str,
        articles: list[Article],
    ) -> None:
        available = self._available_sources(articles)

        available_lookup = {
            value.lower(): value
            for value in available
        }

        if source.lower() not in available_lookup:
            raise InvalidSourceError(
                f"Unknown source: {source}.\n"
                f"Available sources: {', '.join(available)}"
            )

    async def update(
        self,
        *,
        force_refresh: bool = False,
    ) -> UpdateResult:
        """
        Refresh the local article cache.

        When the cache is valid and force_refresh is False, cached articles
        are returned without downloading or enriching feeds.
        """

        if (
            not force_refresh
            and self._repository.is_cache_valid()
        ):
            logger.info("Using cached articles.")

            cached = self._repository.load()

            return UpdateResult(
                feeds_downloaded=0,
                articles_parsed=len(cached),
                articles_saved=len(cached),
                cache_used=True,
            )

        logger.info("Downloading feeds...")

        feed_results = await self._fetcher.fetch_all()

        logger.info(
            "Fetched %d feeds.",
            len(feed_results),
        )

        articles = self._parser.parse(feed_results)

        logger.info(
            "Parsed %d articles.",
            len(articles),
        )

        if not articles:
            logger.warning(
                "No articles parsed. Cache not refreshed."
            )

            return UpdateResult(
                feeds_downloaded=len(feed_results),
                articles_parsed=0,
                articles_saved=0,
                cache_used=False,
            )

        logger.info(
            "Enriching %d articles.",
            len(articles),
        )

        enriched_articles = await self._enrichment_pipeline.enrich_many(
            articles
        )

        logger.info(
            "Enriched %d articles.",
            len(enriched_articles),
        )

        self._repository.refresh(enriched_articles)

        logger.info("Cache refreshed.")

        return UpdateResult(
            feeds_downloaded=len(feed_results),
            articles_parsed=len(articles),
            articles_saved=len(enriched_articles),
            cache_used=False,
        )

    async def latest(
        self,
        query: LatestQuery,
    ) -> list[Article]:

        articles = self._repository.load()

        if query.category:
            self._validate_category(
                query.category,
                articles,
            )

            requested_category = query.category.casefold()

            articles = [
                article
                for article in articles
                if article.category
                and article.category.casefold() == requested_category
            ]


        if query.source:
            self._validate_source(
                query.source,
                articles,
            )

            requested_source = query.source.casefold()

            articles = [
                article
                for article in articles
                if article.source
                and article.source.casefold() == requested_source
            ]

        if query.tag:
            requested_tag = query.tag.casefold()

            articles = [
                article
                for article in articles
                if any(
                    tag.casefold() == requested_tag
                    for tag in article.tags
                )
            ]

        articles.sort(
            key=lambda article: article.published or datetime.min,
            reverse=True,
        )

        return articles[:query.limit]

    async def by_source(
        self,
        source: str,
        limit: int = 20,
    ) -> list[Article]:

        articles = self._repository.load()

        self._validate_source(source, articles)

        source_lower = source.lower()

        filtered_articles = [
            article
            for article in articles
            if article.source.lower() == source_lower
        ]

        return filtered_articles[:limit]

    async def by_category(
        self,
        category: str,
        limit: int = 20,
    ) -> list[Article]:

        articles = self._repository.load()

        self._validate_category(category, articles)

        category_lower = category.lower()

        filtered_articles = [
            article
            for article in articles
            if article.category.lower() == category_lower
        ]

        return filtered_articles[:limit]