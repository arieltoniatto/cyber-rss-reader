from __future__ import annotations

from typing import Protocol

from parser.models import Article


class ArticleEnricher(Protocol):
    """
    Interface implemented by every article enrichment component.

    Each enricher receives an Article and returns an enriched Article.
    Enrichers should avoid mutating the original article directly.
    """

    @property
    def name(self) -> str:
        """Human-readable enricher name used in logs."""
        ...

    async def enrich(self, article: Article) -> Article:
        """
        Enrich a single article.

        Args:
            article: Article to enrich.

        Returns:
            A new enriched Article instance.
        """
        ...