from __future__ import annotations

from abc import ABC, abstractmethod

from parser.models import Article


class ArticleRepository(ABC):
    """
    Abstract storage interface.
    """

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