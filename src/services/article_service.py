from __future__ import annotations

import logging

from feeds.fetcher import RSSFetcher
from parser.models import Article
from parser.parser import RSSParser
from storage.interfaces import ArticleRepository
from services.models import UpdateResult


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
    ) -> None:

        self._repository = repository
        self._fetcher = fetcher
        self._parser = parser

    async def update(
        self,
        *,
        force_refresh: bool = False,
    ) -> UpdateResult:
        """
        Refresh local cache.

        Returns the current article collection.
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

        if articles:
            self._repository.refresh(articles)
        else:
            logger.warning(
                "No articles parsed. Cache not refreshed."
            )

        logger.info("Cache refreshed.")

        return UpdateResult(
            feeds_downloaded=len(feed_results),
            articles_parsed=len(articles),
            articles_saved=len(articles),
            cache_used=False,
        )

    async def latest(
        self,
        *,
        limit: int = 20,
    ) -> list[Article]:
        """
        Return newest cached articles.
        """

        articles = self._repository.load()

        articles.sort(
            key=lambda article: (
                article.published is None,
                article.published,
            ),
            reverse=True,
        )

        return articles[:limit]

    async def by_source(
        self,
        source: str,
    ) -> list[Article]:

        source = source.lower()

        return [
            article
            for article in self._repository.load()
            if article.source.lower() == source
        ]

    async def by_category(
        self,
        category: str,
    ) -> list[Article]:

        category = category.lower()

        return [
            article
            for article in self._repository.load()
            if article.category.lower() == category
        ]