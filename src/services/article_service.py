from __future__ import annotations

import logging
from datetime import datetime, timezone
from dataclasses import replace
from config.models import FeedConfiguration
from feeds.models import FeedObservation
from parser.dates import publication_key
from storage.utils import article_key

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

        if category.casefold() not in {value.casefold() for value in available}:
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

        configuration = getattr(self._fetcher, "configuration", None)
        configured_feeds = [feed for category in configuration.categories for feed in category.feeds] \
            if isinstance(configuration, FeedConfiguration) else []
        self._repository.begin_feed_collection(configured_feeds)
        try:
            feed_results = await self._fetcher.fetch_all()
        except Exception as exc:
            now = datetime.now(timezone.utc)
            self._repository.save_collection([], [FeedObservation(
                feed=feed, attempted_at=now, completed_at=now,
                error=f"{type(exc).__name__}: {exc}",
            ) for feed in configured_feeds])
            raise

        articles: list[Article] = []
        observations: list[FeedObservation] = []
        for result in feed_results:
            error = result.error
            parsed_articles = []
            if error is None:
                try:
                    parsed_articles = self._parser.parse([result])
                except Exception as exc:
                    error = f"Parser {type(exc).__name__}: {exc}"
                    logger.exception("Parsing failed for %s", result.feed.name)
            articles.extend(parsed_articles)
            observations.append(FeedObservation(
                feed=result.feed, attempted_at=result.attempted_at,
                completed_at=datetime.now(timezone.utc), error=error,
                article_count=len({article_key(a) for a in parsed_articles}),
                warnings=result.warnings,
            ))

        logger.info("Attempted %d feeds; parsed %d articles", len(feed_results), len(articles))
        try:
            enriched = await self._enrichment_pipeline.enrich_many(articles) if articles else []
            completed_at = datetime.now(timezone.utc)
            observations = [replace(o, completed_at=completed_at) for o in observations]
            self._repository.save_collection(enriched, observations)
        except Exception as exc:
            failed = [replace(o, completed_at=datetime.now(timezone.utc), article_count=0,
                              error=o.error or f"Processing {type(exc).__name__}: {exc}")
                      for o in observations]
            self._repository.save_collection([], failed)
            raise

        failures = sum(o.error is not None for o in observations)
        logger.info("Saved %d unique articles; %d feeds failed", len({article_key(a) for a in enriched}), failures)
        return UpdateResult(
            feeds_downloaded=sum(result.error is None for result in feed_results),
            feeds_failed=failures,
            articles_parsed=len(articles),
            articles_saved=len({article_key(article) for article in enriched}),
            cache_used=False,
        )

    async def latest(
        self,
        query: LatestQuery,
    ) -> list[Article]:

        return self._repository.latest(
            category=query.category, source=query.source, tag=query.tag,
            limit=query.limit, offset=query.offset,
        )

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

        return sorted(filtered_articles, key=publication_key, reverse=True)[:limit]

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
            if article.category and article.category.lower() == category_lower
        ]

        return sorted(filtered_articles, key=publication_key, reverse=True)[:limit]