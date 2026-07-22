from __future__ import annotations

from parser.models import Article

from ..interfaces import TopicExtractor
from ..models import Topic


class RAKETopicExtractor(TopicExtractor):
    """
    Placeholder implementation.

    Intended for future integration with
    rake-nltk.
    """

    def extract(
        self,
        articles: list[Article],
        *,
        limit: int = 20,
    ) -> list[Topic]:

        raise NotImplementedError(
            "RAKE extractor not implemented."
        )