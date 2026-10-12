from __future__ import annotations

from abc import ABC, abstractmethod

from parser.models import Article
from parser.dates import publication_key
from feeds.models import FeedObservation
from config.models import Feed
from collections import Counter
from storage.utils import article_key
from storage.retention import RetentionResult


class ArticleRepository(ABC):
    """
    Abstract storage interface.
    """

    def begin_feed_collection(self, feeds: list[Feed]) -> None:
        """Legacy repositories do not persist collection telemetry."""

    def save_collection(self, articles: list[Article], observations: list[FeedObservation]) -> RetentionResult | None:
        if articles:
            self.refresh(articles)

    def feed_status(self) -> list[dict]:
        return []

    def get(self, article_id: str) -> Article | None:
        return next((a for a in self.load() if article_key(a) == article_id), None)

    def filters(self) -> dict:
        articles = self.load()
        def counts(values):
            return [{'value': value, 'count': count} for value, count in sorted(Counter(values).items())]
        return {'total': len(articles),
                'categories': counts(a.category for a in articles if a.category),
                'sources': counts(a.source for a in articles if a.source),
                'tags': counts(tag for a in articles for tag in set(a.tags))}

    def latest(self, *, category=None, source=None, tag=None,
               limit: int = 20, offset: int = 0) -> list[Article]:
        articles = self.load()
        if category:
            articles = [a for a in articles if a.category and
                        a.category.casefold() == category.casefold()]
        if source:
            articles = [a for a in articles if a.source.casefold() == source.casefold()]
        if tag:
            articles = [a for a in articles if any(t.casefold() == tag.casefold()
                                                  for t in a.tags)]
        return sorted(articles, key=publication_key, reverse=True)[offset:offset + limit]

    @abstractmethod
    def save(self, articles: list[Article]) -> None:
        ...

    @abstractmethod
    def load(self) -> list[Article]:
        ...

    @abstractmethod
    def clear(self) -> None:
        ...

    @abstractmethod
    def refresh(self, articles: list[Article]) -> None:
        ...

    @abstractmethod
    def is_cache_valid(self) -> bool:
        ...
