from __future__ import annotations

import logging
from datetime import timedelta
from pathlib import Path

from config.loader import ConfigLoader

from config.models import FeedConfiguration
from feeds.fetcher import RSSFetcher

from parser.parser import RSSParser

from search.engine import SearchEngine

from services.arcticle_service import ArticleService

from services.search_service import SearchService
from services.topic_service import TopicService
from storage.json_storage import JsonArticleRepository

from storage.models import ArticleRepository
from topics.algorithms.tfidf import TFIDFTopicExtractor
from topics.extractor import TopicExtractionService

from .container import ApplicationContainer


def configure_logging(
    level: int = logging.INFO,
) -> None:
    """
    Configure application logging.
    """

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def bootstrap(
    *,
    config_directory: Path = Path("config/feeds"),
    cache_file: Path = Path("data/articles.json"),
    cache_duration: timedelta = timedelta(hours=6),
) -> ApplicationContainer:
    """
    Create every application dependency.

    This is the composition root of the application.
    """
    configuration: FeedConfiguration

    repository: ArticleRepository

    fetcher: RSSFetcher
    parser: RSSParser

    search_engine: SearchEngine
    topic_service: TopicExtractionService

    article_service: ArticleService

    ####################################################################
    # Logging
    ####################################################################

    configure_logging()

    logger = logging.getLogger(__name__)

    logger.info("Loading configuration...")

    ####################################################################
    # Configuration
    ####################################################################

    configuration = ConfigLoader(
        config_directory,
    ).load()

    print(configuration)
    print(
        "Categories loaded:",
        len(configuration.categories)
    )

    repository = JsonArticleRepository(
        cache_file=cache_file,
        cache_duration=cache_duration,
    )

    fetcher = RSSFetcher(configuration)

    parser = RSSParser()

    search_engine = SearchEngine()

    topic_service = TopicExtractionService(
        TFIDFTopicExtractor(),
    )

    logger.info(
        "Loaded %d categories.",
        len(configuration.categories),
    )

    ####################################################################
    # Repository
    ####################################################################

    repository = JsonArticleRepository(
        cache_file=cache_file,
        cache_duration=cache_duration,
    )

    ####################################################################
    # Search Engine
    ####################################################################

    search_engine = SearchEngine()

    ####################################################################
    # Topic Extraction
    ####################################################################

    topic_extractor = TopicExtractionService(
        TFIDFTopicExtractor(),
    )

    ###############################################################
    # Infrastructure
    ###############################################################

    fetcher = RSSFetcher(
        configuration,
    )

    parser = RSSParser()

    repository = JsonArticleRepository(
        cache_file=cache_file,
        cache_duration=cache_duration,
    )

    ###############################################################
    # Domain
    ###############################################################

    search_engine = SearchEngine()

    topic_extractor = TopicExtractionService(
        TFIDFTopicExtractor(),
    )

    ###############################################################
    # Application Services
    ###############################################################

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
    

    logger.info("Bootstrap completed.")

    ###############################################################
    # Container
    ###############################################################

    return ApplicationContainer(

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