from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from parser.models import Article
from storage.json_storage import JsonArticleRepository
from storage.sqlite_storage import SQLiteArticleRepository


def article(title="A", source="Source", **kwargs):
    return Article(title=title, source=source, summary="malware report",
                   url=f"https://example.com/{title}", **kwargs)


def test_refresh_preserves_history_and_updates_existing_articles(tmp_path):
    repo = SQLiteArticleRepository(tmp_path / "archive.sqlite3")
    repo.refresh([article("A"), article("B", source="Unavailable")])
    repo.refresh([replace(article("A"), malware=["BlackEnergy"])])
    assert len(repo.load()) == 2
    assert repo.latest(source="SOURCE")[0].malware == ["BlackEnergy"]
    assert repo.is_cache_valid()
    repo.refresh([])
    assert len(repo.load()) == 2


def test_pagination_filtering_and_null_dates(tmp_path):
    repo = SQLiteArticleRepository(tmp_path / "archive.sqlite3")
    repo.refresh([article("A", tags=["Ransomware"], category="News",
                          published=datetime(2026, 1, 1, tzinfo=timezone.utc)),
                  article("B", tags=["Ransomware"], category="News",
                          published=datetime(2026, 2, 1)), article("C")])
    assert [a.title for a in repo.latest()] == ["B", "A", "C"]
    assert [a.title for a in repo.latest(category="NEWS", tag="ransomware", limit=1, offset=1)] == ["A"]
    assert repo.latest(source="Unknown") == []


def test_transaction_rolls_back_entire_batch(tmp_path):
    repo = SQLiteArticleRepository(tmp_path / "archive.sqlite3")
    repo.refresh([article("Old")])
    with pytest.raises(AttributeError):
        repo.refresh([article("New"), replace(article("Invalid"), tags=[None])])
    assert [a.title for a in repo.load()] == ["Old"]


def test_concurrent_writers_do_not_lose_articles(tmp_path):
    repo = SQLiteArticleRepository(tmp_path / "archive.sqlite3")
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda i: repo.refresh([article(str(i))]), range(20)))
    assert len(repo.load()) == 20


def test_json_import_is_idempotent_and_keeps_original(tmp_path):
    cache = tmp_path / "articles.json"
    JsonArticleRepository(cache, timedelta(hours=6)).save([article(malware=["BlackEnergy"])])
    original = cache.read_bytes()
    repo = SQLiteArticleRepository(tmp_path / "archive.sqlite3")
    assert repo.import_json(cache) == 1
    assert repo.import_json(cache) == 0
    assert repo.load()[0].malware == ["BlackEnergy"]
    assert cache.read_bytes() == original
    assert not repo.is_cache_valid()  # Importing old data must not postpone collection.


def test_filter_choices_include_archived_articles_and_ignore_duplicate_tags(tmp_path):
    from storage.utils import article_key

    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    archived = article('Old', source='Archived source', category='news', tags=['Malware', 'Malware'])
    repo.save([archived, article('New', category='malware', tags=['Malware'])])
    filters = repo.filters()
    assert filters['total'] == 2
    assert filters['tags'] == [{'value': 'Malware', 'count': 2}]
    assert {'value': 'Archived source', 'count': 1} in filters['sources']
    assert repo.get(article_key(archived)) == archived
    assert repo.get('missing') is None
