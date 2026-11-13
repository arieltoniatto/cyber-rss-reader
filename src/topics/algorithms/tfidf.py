from __future__ import annotations

from collections import Counter

from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer

from parser.models import Article

from ..interfaces import TopicExtractor
from ..models import Topic
from ..preprocessing import build_documents


# Some feeds (e.g. NIC.br) publish in Brazilian Portuguese; without these,
# function words like "de" and "para" dominate the ranking.
PORTUGUESE_STOP_WORDS = frozenset("""
a à ao aos apenas após aquela aquelas aquele aqueles aquilo as às assim até
cada com como contra da das de dela delas dele deles depois desde do dos
durante e é ela elas ele eles em entre era eram essa essas esse esses esta
está estão estas este estes eu foi foram há isso isto já lhe lhes mais mas
me mesma mesmo meu minha muito na não nas nem no nos nós nossa nosso num
numa o onde os ou outra outras outro outros para pela pelas pelo pelos pode
podem pois por porque qual quando que quem se sem ser será seu seus sido
sobre sua suas são também te tem têm ter toda todas todo todos um uma umas
uns vai vão você
""".split())

STOP_WORDS = sorted(ENGLISH_STOP_WORDS | PORTUGUESE_STOP_WORDS)


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
            stop_words=STOP_WORDS,
            ngram_range=(1, 2),
            max_features=500,
        )

        try:
            matrix = vectorizer.fit_transform(documents)
        except ValueError as exc:
            if "empty vocabulary" in str(exc):
                return []
            raise

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