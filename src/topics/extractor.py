from __future__ import annotations

from parser.models import Article

from .interfaces import TopicExtractor
from .models import Topic


class TopicExtractionService:
    """
    High-level service using dependency injection.

    The service is independent of the
    concrete extraction algorithm.
    """

    def __init__(
        self,
        extractor: TopicExtractor,
    ) -> None:

        self.extractor = extractor

    def extract(
        self,
        articles: list[Article],
        *,
        limit: int = 20,
    ) -> list[Topic]:

        return self.extractor.extract(
            articles,
            limit=limit,
        )