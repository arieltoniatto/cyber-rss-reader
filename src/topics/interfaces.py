from __future__ import annotations

from abc import ABC, abstractmethod

from parser.models import Article

from .models import Topic


class TopicExtractor(ABC):
    """
    Interface implemented by every topic extraction algorithm.
    """

    @abstractmethod
    def extract(
        self,
        articles: list[Article],
        *,
        limit: int = 20,
    ) -> list[Topic]:
        ...