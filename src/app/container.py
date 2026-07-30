from __future__ import annotations

import logging
from datetime import timedelta
from pathlib import Path

from config.paths import (
    ARTICLE_CACHE_FILE,
    FEED_DIRECTORY,
    THREAT_ACTOR_CATALOG_FILE,
)
from config.loader import ConfigLoader
from config.models import FeedConfiguration
from enrichment.pipeline import EnrichmentPipeline
from enrichment.tag_enricher import TagEnricher
from enrichment.ioc_enricher import IOCEnricher
from enrichment.threat_actor_enricher import ThreatActorEnricher
from feeds.fetcher import RSSFetcher
from parser.parser import RSSParser
from search.engine import SearchEngine
from services.article_service import ArticleService
from services.search_service import SearchService
from services.topic_service import TopicExtractionService
from services.topic_service import TopicService
from storage.interfaces import ArticleRepository
from storage.json_storage import JsonArticleRepository
from topics.algorithms.tfidf import TFIDFTopicExtractor


class ApplicationContainer:
    """
    Application dependency-injection container.

    Creates and wires all application dependencies during initialization.
    """

    def __init__(
        self,
        *,
        config_directory: Path = FEED_DIRECTORY,
        cache_file: Path = ARTICLE_CACHE_FILE,
        cache_duration: timedelta = timedelta(hours=6),
        log_level: int = logging.WARNING,
    ) -> None:

        config_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        cache_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._configure_logging(log_level)

        logger = logging.getLogger(__name__)

        logger.info("Loading configuration...")

        ################################################################
        # Configuration
        ################################################################

        self.configuration: FeedConfiguration = ConfigLoader(
            config_directory,
        ).load()

        ################################################################
        # Infrastructure
        ################################################################

        self.repository: ArticleRepository = JsonArticleRepository(
            cache_file=cache_file,
            cache_duration=cache_duration,
        )

        self.fetcher = RSSFetcher(
            self.configuration,
        )

        self.parser = RSSParser()

        ################################################################
        # Search
        ################################################################

        self.search_engine = SearchEngine()

        ################################################################
        # Topic extraction
        ################################################################

        self.topic_extractor = TopicExtractionService(
            TFIDFTopicExtractor(),
        )

        ################################################################
        # Enrichment
        ################################################################

        self.tag_enricher = TagEnricher()

        self.ioc_enricher = IOCEnricher()

        self.threat_actor_enricher = (
            ThreatActorEnricher(
                catalog_file=THREAT_ACTOR_CATALOG_FILE,
            )
        )

        self.enrichment_pipeline = EnrichmentPipeline(
            enrichers=[
                self.tag_enricher,
                self.ioc_enricher,
                self.threat_actor_enricher,
            ],
            continue_on_error=True,
        )

        ################################################################
        # Services
        ################################################################

        self.article_service = ArticleService(
            repository=self.repository,
            fetcher=self.fetcher,
            parser=self.parser,
            enrichment_pipeline=self.enrichment_pipeline,
        )

        self.search_service = SearchService(
            repository=self.repository,
            engine=self.search_engine,
        )

        self.topic_service = TopicService(
            repository=self.repository,
            extractor=self.topic_extractor,
        )

        logger.info("Application initialized.")

    @staticmethod
    def _configure_logging(
        log_level: int,
    ) -> None:
        logging.basicConfig(
            level=log_level,
            format=(
                "%(asctime)s | "
                "%(levelname)s | "
                "%(name)s | "
                "%(message)s"
            ),
        )