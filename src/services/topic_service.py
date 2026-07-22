from __future__ import annotations

from parser.models import Article
from storage.interfaces import ArticleRepository
from topics.extractor import TopicExtractionService
from topics.models import Topic


class TopicService:
    """
    Application service responsible for topic extraction.

    Responsibilities:
        - Load cached articles
        - Delegate extraction to the configured TopicExtractionService

    This class contains no extraction logic.
    """

    def __init__(
        self,
        *,
        repository: ArticleRepository,
        extractor: TopicExtractionService,
    ) -> None:
        self._repository = repository
        self._extractor = extractor

    async def extract(
        self,
        *,
        limit: int = 20,
    ) -> list[Topic]:
        """
        Extract topics from cached articles.
        """

        articles = self._repository.load()

        return self._extractor.extract(
            articles,
            limit=limit,
        )

    async def extract_from_articles(
        self,
        articles: list[Article],
        *,
        limit: int = 20,
    ) -> list[Topic]:
        """
        Extract topics from a supplied collection of articles.

        Useful for:
        - tests
        - REST API
        - plugins
        - future pipelines
        """

        return self._extractor.extract(
            articles,
            limit=limit,
        )