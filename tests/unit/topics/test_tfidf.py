from parser.models import Article
from topics.algorithms.tfidf import TFIDFTopicExtractor


def test_empty_vocabulary_returns_no_topics():
    article = Article(title="the and", source="Source", summary="", url="")
    assert TFIDFTopicExtractor().extract([article]) == []


def test_portuguese_function_words_are_not_topics():
    articles = [
        Article(title="Guia de segurança para crianças", source="NIC.br",
                summary="O CERT.br publica um guia com alertas sobre golpes e para os educadores.", url=""),
        Article(title="Brasil amplia o uso de IPv6", source="NIC.br",
                summary="A adoção de IPv6 cresce entre os provedores e na rede.", url=""),
    ]
    topics = {topic.topic for topic in TFIDFTopicExtractor().extract(articles, limit=50)}
    assert topics.isdisjoint({"de", "para", "os", "um", "com", "na", "sobre", "entre"})
    assert "ipv6" in topics
