from parser.models import Article
from topics.algorithms.tfidf import TFIDFTopicExtractor


def test_empty_vocabulary_returns_no_topics():
    article = Article(title="the and", source="Source", summary="", url="")
    assert TFIDFTopicExtractor().extract([article]) == []
