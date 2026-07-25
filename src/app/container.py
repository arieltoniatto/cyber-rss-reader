from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from config.paths import ARTICLE_CACHE_FILE, LOG_DIRECTORY, DATA_DIRECTORY, FEED_DIRECTORY
from config.loader import ConfigLoader
from config.models import FeedConfiguration

from feeds.fetcher import RSSFetcher

from parser.parser import RSSParser

from search.engine import SearchEngine

from services.article_service import ArticleService
from services.search_service import SearchService
from services.topic_service import TopicService

from storage.interfaces import ArticleRepository
from storage.json_storage import JsonArticleRepository

from topics.algorithms.tfidf import TFIDFTopicExtractor
from topics.extractor import TopicExtractionService

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_FEEDS_DIR = FEED_DIRECTORY
DEFAULT_CACHE_FILE = ARTICLE_CACHE_FILE
DEFAULT_DATA_DIR = DATA_DIRECTORY
DEFAULT_LOGS_DIR = LOG_DIRECTORY


@dataclass(slots=True)
class ApplicationContainer:
    """
    Root Dependency Injection Container.

    This is the application's Composition Root.

    Every concrete implementation is instantiated here exactly once.
    """

    ####################################################################
    # Infrastructure
    ####################################################################

    configuration: FeedConfiguration

    repository: ArticleRepository

    fetcher: RSSFetcher

    parser: RSSParser

    ####################################################################
    # Domain
    ####################################################################

    search_engine: SearchEngine

    topic_extractor: TopicExtractionService

    ####################################################################
    # Application Services
    ####################################################################

    article_service: ArticleService

    search_service: SearchService

    topic_service: TopicService

    ####################################################################
    # Factory
    ####################################################################

    @classmethod
    def build(
        cls,
        *,
        config_directory: Path | None = None,
        cache_file: Path | None = None,
        cache_duration: timedelta = timedelta(hours=6),
        log_level: int = logging.WARNING,
    ) -> "ApplicationContainer":

        config_directory = config_directory or DEFAULT_FEEDS_DIR
        cache_file = cache_file or DEFAULT_CACHE_FILE

        # Ensure directories exist
        config_directory.mkdir(parents=True, exist_ok=True)
        cache_file.parent.mkdir(parents=True, exist_ok=True)

        cls._configure_logging(log_level)

        logger = logging.getLogger(__name__)

        logger.info("Loading configuration...")

        ################################################################
        # Configuration
        ################################################################

        configuration = ConfigLoader(
            config_directory,
        ).load()

        ################################################################
        # Infrastructure
        ################################################################

        repository = JsonArticleRepository(
            cache_file=ARTICLE_CACHE_FILE,
            cache_duration=cache_duration,
        )

        fetcher = RSSFetcher(
            configuration,
        )

        parser = RSSParser()

        ################################################################
        # Domain
        ################################################################

        search_engine = SearchEngine()

        topic_extractor = TopicExtractionService(
            TFIDFTopicExtractor(),
        )

        ################################################################
        # Application Services
        ################################################################

        article_service = ArticleService(
            repository=repository,
            fetcher=fetcher,
            parser=parser,
        )

        search_service = SearchService(
            repository=repository,
            engine=search_engine,
        )

        topic_service = TopicService(
            repository=repository,
            extractor=topic_extractor,
        )

        logger.info("Application initialized.")

        return cls(
            configuration=configuration,

            repository=repository,

            fetcher=fetcher,

            parser=parser,

            search_engine=search_engine,

            topic_extractor=topic_extractor,

            article_service=article_service,

            search_service=search_service,

            topic_service=topic_service,
        )

    ####################################################################
    # Private Helpers
    ####################################################################

    @staticmethod
    def _configure_logging(
        level: int,
    ) -> None:

        logging.basicConfig(
            level=level,
            format=(
                "%(asctime)s | "
                "%(levelname)s | "
                "%(name)s | "
                "%(message)s"
            ),
        )