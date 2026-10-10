from __future__ import annotations

from dataclasses import dataclass

from services.article_service import ArticleService
from services.search_service import SearchService
from services.topic_service import TopicService
from services.attack_service import AttackService
from services.vulnerability_service import VulnerabilityService


@dataclass(slots=True)
class CLIServices:
    """
    Exposes only the services required by the CLI.

    The CLI should never access repositories,
    parsers, fetchers, or other infrastructure directly.
    """

    article_service: ArticleService

    search_service: SearchService

    topic_service: TopicService
    attack_service: AttackService | None = None
    vulnerability_service: VulnerabilityService | None = None
