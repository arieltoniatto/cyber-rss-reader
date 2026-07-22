from __future__ import annotations

from collections import Counter

from sklearn.feature_extraction.text import TfidfVectorizer

from parser.models import Article

from ..interfaces import TopicExtractor
from ..models import Topic
from ..preprocessing import build_documents


class TFIDFTopicExtractor(TopicExtractor):
    """
    TF-IDF implementation.

    Can be replaced later without changing
    the rest of the application.
    """

    def extract(
        self,
        articles: list[Article],
        *,
        limit: int = 20,
    ) -> list[Topic]:

        if not articles:
            return []

        documents = build_documents(articles)

        vectorizer = TfidfVectorizer(
            stop_words="english",
            ngram_range=(1, 2),
            max_features=500,
        )

        matrix = vectorizer.fit_transform(documents)

        scores = matrix.sum(axis=0).A1

        vocabulary = vectorizer.get_feature_names_out()

        frequencies = Counter()

        for document in documents:
            frequencies.update(document.split())

        ranked = sorted(
            zip(vocabulary, scores),
            key=lambda item: item[1],
            reverse=True,
        )

        topics = []

        for word, score in ranked[:limit]:

            topics.append(
                Topic(
                    topic=word,
                    score=float(score),
                    frequency=frequencies.get(
                        word.split()[0],
                        0,
                    ),
                )
            )

        return topics