from datetime import datetime, timedelta, timezone

from parser.models import Article, IOC, IOCType
from storage.json_storage import JsonArticleRepository
from storage.utils import article_key


def test_round_trip_preserves_enrichment_and_normalizes_legacy_dates(tmp_path):
    article = Article(title="Test", source="Source", summary="", url="https://example.com/A",
                      published=datetime(2026, 1, 1), malware=["BlackEnergy"],
                      threat_actors=["APT28"], tags=["malware"],
                      iocs=[IOC(IOCType.CVE, "CVE-2026-1234")])
    repository = JsonArticleRepository(tmp_path / "cache.json", timedelta(hours=6))
    repository.save([article])
    restored = repository.load()[0]
    assert restored.malware == article.malware
    assert restored.iocs == article.iocs
    assert restored.threat_actors == article.threat_actors
    assert restored.published == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert repository.is_cache_valid()


def test_identity_preserves_case_sensitive_paths_and_missing_urls():
    def article(title, url=""):
        return Article(title=title, source="Source", summary="", url=url)
    assert article_key(article("A")) != article_key(article("B"))
    assert article_key(article("A", "https://EXAMPLE.com/A")) == article_key(article("A", "https://example.com/A#fragment"))
    assert article_key(article("A", "https://example.com/A")) != article_key(article("A", "https://example.com/a"))
