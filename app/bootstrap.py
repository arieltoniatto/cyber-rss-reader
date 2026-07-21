from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from cli import create_cli
from cli.dependencies import ApplicationServices
from config.loader import ConfigLoader
from feeds.fetcher import RSSFetcher
from parser.parser import RSSParser
from search.engine import SearchEngine
from storage.json_storage import JsonArticleRepository
from topics import TFIDFTopicExtractor, TopicExtractionService


class ArticleService:
    """
    Facade used by the CLI.

    This is intentionally lightweight and serves as the integration
    point between the CLI and the underlying modules.
    """

    def _init_(
        self,
        repository: JsonArticleRepository,
        fetcher: RSSFetcher,
        parser: RSSParser,
    ) -> None:

        self.repository = repository
        self.fetcher = fetcher
        self.parser = parser

    def update(self):
        """
        Download feeds, parse articles and refresh cache.
        """

        import asyncio

        feed_results = asyncio.run(
            self.fetcher.fetch_all()
        )

        articles = self.parser.parse(feed_results)

        self.repository.refresh(articles)

        return articles

    def latest(self, limit: int = 20):

        articles = self.repository.load()

        articles.sort(
            key=lambda article: (
                article.published is not None,
                article.published,
            ),
            reverse=True,
        )

        return articles[:limit]

    def by_source(self, source: str):

        return [
            article
            for article in self.repository.load()
            if article.source.lower() == source.lower()
        ]

    def by_category(self, category: str):

        return [
            article
            for article in self.repository.load()
            if article.category.lower() == category.lower()
        ]


class SearchService:

    def _init_(
        self,
        repository: JsonArticleRepository,
        engine: SearchEngine,
    ) -> None:

        self.repository = repository
        self.engine = engine

    def search(
        self,
        *,
        keyword: str,
        category: str | None = None,
        source: str | None = None,
        limit: int = 20,
    ):

        from search import (
            SearchFilters,
            SearchQuery,
        )

        articles = self.repository.load()

        query = SearchQuery(
            include={keyword},
            optional=set(),
            exclude=set(),
        )

        filters = SearchFilters(
            category=category,
            source=source,
            limit=limit,
        )

        return self.engine.search(
            articles,
            query,
            filters,
        )


class TopicsService:

    def _init_(
        self,
        repository: JsonArticleRepository,
        extractor: TopicExtractionService,
    ) -> None:

        self.repository = repository
        self.extractor = extractor

    def extract(
        self,
        *,
        limit: int = 20,
    ):

        return self.extractor.extract(
            self.repository.load(),
            limit=limit,
        )


def bootstrap():
    """
    Builds the application dependency graph.
    """

    config = ConfigLoader(
        Path("config/feeds")
    ).load()

    repository = JsonArticleRepository(
        cache_file=Path("data/articles.json"),
        cache_duration=timedelta(hours=6),
    )

    fetcher = RSSFetcher(config)

    parser = RSSParser()

    search_engine = SearchEngine()

    topic_service = TopicExtractionService(
        TFIDFTopicExtractor()
    )

    services = ApplicationServices(

        article_service=ArticleService(
            repository,
            fetcher,
            parser,
        ),

        search_service=SearchService(
            repository,
            search_engine,
        ),

        topic_service=TopicsService(
            repository,
            topic_service,
        ),
    )

    return create_cli(services)