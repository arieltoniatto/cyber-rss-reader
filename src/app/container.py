from __future__ import annotations

import logging
import asyncio
import os
from datetime import timedelta
from pathlib import Path

from config.structured_logging import configure_logging_from_environment
from config.paths import (
    ARTICLE_DATABASE_FILE,
    ATTACK_MAPPING_CATALOG_FILE,
    FEED_DIRECTORY,
    MALWARE_CATALOG_FILE,
    MISP_GALAXY_SEED_FILE,
    MISP_GALAXY_SEED_METADATA,
    THREAT_ACTOR_OVERRIDES_FILE,
    THREAT_ACTOR_CATALOG_FILE,
)
from config.loader import ConfigLoader
from config.feed_registry import FeedRegistry
from enrichment.pipeline import EnrichmentPipeline
from enrichment.tag_enricher import TagEnricher
from enrichment.ioc_enricher import IOCEnricher
from enrichment.malware_enricher import MalwareEnricher
from enrichment.threat_actor_enricher import ThreatActorEnricher
from enrichment.attack_enricher import AttackEnricher
from enrichment.cve_enricher import CVEEnricher
from services.vulnerability_service import VulnerabilityService
from cti.attack_mapping import AttackCatalog
from cti.misp_galaxy_store import MispGalaxyStore
from services.attack_service import AttackService
from feeds.fetcher import RSSFetcher
from alerts.service import AlertService
from alerts.config import AlertSettings
from parser.parser import RSSParser
from search.engine import SearchEngine
from services.article_service import ArticleService
from services.search_service import SearchService
from services.topic_service import TopicExtractionService
from services.topic_service import TopicService
from storage.interfaces import ArticleRepository
from storage.sqlite_storage import SQLiteArticleRepository
from storage.factory import create_repository, is_postgres
from storage.locks import collector_lock
from config.postgres_feed_registry import PostgreSQLFeedRegistry
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
        cache_file: Path | None = None,
        database_file: Path = ARTICLE_DATABASE_FILE,
        cache_duration: timedelta = timedelta(hours=6),
        log_level: int = logging.WARNING,
        misp_auto_update: bool | None = None,
        database_url: str | None = None,
    ) -> None:

        self._configure_logging(log_level)

        logger = logging.getLogger(__name__)

        logger.info("Loading configuration...")

        ################################################################
        # Configuration and infrastructure
        ################################################################

        self.repository: ArticleRepository = create_repository(
            database_file=database_file, cache_file=cache_file, database_url=database_url,
            cache_duration=cache_duration)
        self.lock_target = self.repository if is_postgres(self.repository) else database_file

        self.feed_registry = (PostgreSQLFeedRegistry(self.repository, config_directory) if is_postgres(self.repository)
                              else FeedRegistry(database_file, config_directory)
                              if isinstance(self.repository, SQLiteArticleRepository) else None)
        self.configuration = (self.feed_registry.configuration() if self.feed_registry is not None
                              else ConfigLoader(config_directory).load())

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

        self.malware_enricher = MalwareEnricher(
            catalog_file=MALWARE_CATALOG_FILE,
        )

        self.misp_store = MispGalaxyStore(
            (cache_file.parent if cache_file is not None else database_file.parent) / 'misp-galaxy',
            MISP_GALAXY_SEED_FILE, MISP_GALAXY_SEED_METADATA,
            interval_hours=float(os.environ.get('CYBER_RSS_MISP_UPDATE_INTERVAL_HOURS', '168')))
        self.misp_auto_update = (os.environ.get('CYBER_RSS_MISP_AUTO_UPDATE', '1') != '0'
                                 if misp_auto_update is None else misp_auto_update)
        self.threat_actor_enricher = (
            ThreatActorEnricher(
                catalog_file=THREAT_ACTOR_CATALOG_FILE,
                galaxy=self.misp_store.load(),
                overrides_file=THREAT_ACTOR_OVERRIDES_FILE,
            )
        )

        self.attack_catalog = AttackCatalog.load(ATTACK_MAPPING_CATALOG_FILE)
        self.attack_enricher = AttackEnricher(self.attack_catalog)
        self.cve_enricher = CVEEnricher()
        self.vulnerability_service = VulnerabilityService(
            (cache_file.parent if cache_file is not None else database_file.parent) / "cve-cache.sqlite3")

        self.enrichment_pipeline = EnrichmentPipeline(
            enrichers=[
                self.tag_enricher,
                self.ioc_enricher,
                self.malware_enricher,
                self.threat_actor_enricher,
                self.attack_enricher,
                self.cve_enricher,
            ],
            continue_on_error=True,
        )

        ################################################################
        # Services
        ################################################################

        alert_settings = getattr(self.repository, 'alert_settings', AlertSettings())
        self.alert_service = AlertService(self.repository, alert_settings) if alert_settings.active else None

        self.article_service = ArticleService(
            repository=self.repository,
            fetcher=self.fetcher,
            parser=self.parser,
            enrichment_pipeline=self.enrichment_pipeline,
            configuration_loader=self.feed_registry.configuration if self.feed_registry else None,
            before_collection=self._refresh_threat_actor_catalog,
            after_collection=self.alert_service.after_collection if self.alert_service else None,
            collection_lock_factory=lambda: collector_lock(self.lock_target),
        )

        self.search_service = SearchService(
            repository=self.repository,
            engine=self.search_engine,
        )

        self.attack_service = AttackService(self.search_service, self.attack_catalog)

        self.topic_service = TopicService(
            repository=self.repository,
            extractor=self.topic_extractor,
        )

        logger.info("Application initialized.")

    async def _refresh_threat_actor_catalog(self):
        if self.misp_auto_update:
            await asyncio.to_thread(self.misp_store.refresh)
        galaxy = await asyncio.to_thread(self.misp_store.load)
        await asyncio.to_thread(self.threat_actor_enricher.reload, galaxy)

    @staticmethod
    def _configure_logging(
        log_level: int,
    ) -> None:
        if configure_logging_from_environment(log_level):
            return
        logging.basicConfig(
            level=log_level,
            format=(
                "%(asctime)s | "
                "%(levelname)s | "
                "%(name)s | "
                "%(message)s"
            ),
        )
