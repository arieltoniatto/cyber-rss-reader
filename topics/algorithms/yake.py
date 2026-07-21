from __future__ import annotations

from parser.models import Article

from ..interfaces import TopicExtractor
from ..models import Topic


class YAKETopicExtractor(TopicExtractor):
    """
    Placeholder implementation.

    Intended for future YAKE integration.
    """

    def extract(
        self,
        articles: list[Article],
        *,
        limit: int = 20,
    ) -> list[Topic]:

        raise NotImplementedError(
            "YAKE extractor not implemented."
        )