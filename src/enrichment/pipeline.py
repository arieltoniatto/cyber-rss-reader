from __future__ import annotations

import logging
from collections.abc import Iterable

from enrichment.base import ArticleEnricher
from parser.models import Article

logger = logging.getLogger(__name__)


class EnrichmentPipeline:
    """
    Executes article enrichers sequentially.

    Enrichers are executed in registration order. The result returned by one
    enricher becomes the input for the next enricher.
    """

    def __init__(
        self,
        enrichers: Iterable[ArticleEnricher] | None = None,
        *,
        continue_on_error: bool = True,
    ) -> None:
        self._enrichers = list(enrichers or [])
        self._continue_on_error = continue_on_error

    @property
    def enrichers(self) -> tuple[ArticleEnricher, ...]:
        """
        Return the registered enrichers as an immutable tuple.
        """
        return tuple(self._enrichers)

    def register(self, enricher: ArticleEnricher) -> None:
        """
        Register an enricher at the end of the pipeline.

        Args:
            enricher: Enricher to register.
        """
        self._enrichers.append(enricher)

    async def enrich(self, article: Article) -> Article:
        """
        Run all registered enrichers for one article.

        Args:
            article: Article to enrich.

        Returns:
            Fully enriched article.
        """
        enriched_article = article

        for enricher in self._enrichers:
            try:
                enriched_article = await enricher.enrich(enriched_article)
            except Exception:
                logger.exception(
                    "Article enrichment failed",
                    extra={
                        "enricher": enricher.name,
                        "article_title": article.title,
                        "article_url": str(article.url),
                    },
                )

                if not self._continue_on_error:
                    raise

        return enriched_article

    async def enrich_many(
        self,
        articles: Iterable[Article],
    ) -> list[Article]:
        """
        Enrich multiple articles.

        Articles are currently processed sequentially. This is intentional
        because some future enrichers may use rate-limited external APIs.

        Args:
            articles: Articles to enrich.

        Returns:
            Enriched article list.
        """
        enriched_articles: list[Article] = []

        for article in articles:
            enriched_articles.append(await self.enrich(article))

        return enriched_articles