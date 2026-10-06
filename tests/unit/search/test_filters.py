from datetime import datetime, timezone

from parser.models import Article
from search.filters import apply_filters
from search.models import SearchFilters


def test_ordering_handles_missing_and_naive_dates():
    def article(title, published):
        return Article(title=title, source="Source", summary="", url="", published=published)
    articles = [article("Missing", None), article("Old", datetime(2020, 1, 1)),
                article("New", datetime(2026, 1, 1, tzinfo=timezone.utc))]
    assert [a.title for a in apply_filters(articles, SearchFilters(newest=True))] == ["New", "Old", "Missing"]
    assert [a.title for a in apply_filters(articles, SearchFilters(oldest=True))] == ["Missing", "Old", "New"]


def test_category_filter_handles_absent_category():
    article = Article(title="Test", source="Source", summary="", url="")
    assert apply_filters([article], SearchFilters(category="news")) == []
