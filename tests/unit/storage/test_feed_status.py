from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest

from config.models import Feed
from feeds.models import FeedObservation
from parser.models import Article
from storage.sqlite_storage import SQLiteArticleRepository
from storage.migrations import SQLITE_SCHEMA_VERSION
from storage.utils import article_key, article_to_dict


def observation(feed, offset=0, count=2, error=None, warnings=None):
    now = datetime.now(timezone.utc) + timedelta(seconds=offset)
    return FeedObservation(feed=feed, attempted_at=now, completed_at=now,
                           article_count=count, error=error, warnings=warnings or [])


def test_failure_keeps_last_success_and_recovery_clears_error(tmp_path):
    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    feed = Feed(name='Source', url='https://example.com/feed', category='news')
    success = observation(feed)
    repo.save_collection([], [success])
    repo.begin_feed_collection([feed])
    collecting = repo.feed_status()[0]
    assert collecting['status'] == 'collecting'
    assert collecting['last_success'] == success.completed_at.isoformat()
    failed = observation(feed, offset=1, count=0, error='HTTP 404')
    repo.save_collection([], [failed])
    state = repo.feed_status()[0]
    assert state['status'] == 'error'
    assert state['last_error'] == 'HTTP 404'
    assert state['last_success'] == success.completed_at.isoformat()
    assert state['article_count'] == 0
    assert state['last_success_article_count'] == 2
    recovered = observation(feed, offset=2, count=3, warnings=['Malformed XML recovered'])
    repo.save_collection([], [recovered])
    state = repo.feed_status()[0]
    assert state['last_error'] is None
    assert state['last_success'] == recovered.completed_at.isoformat()
    assert state['last_success_article_count'] == 3
    assert state['warnings'] == recovered.warnings
    # An older overlapping cycle must not overwrite more recent telemetry.
    repo.save_collection([], [failed])
    assert repo.feed_status()[0] == state


def test_first_failure_and_empty_success_are_distinct(tmp_path):
    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    feed = Feed(name='Source', url='https://example.com/feed')
    repo.save_collection([], [observation(feed, count=0, error='Timeout')])
    assert repo.feed_status()[0]['last_success'] is None
    assert repo.feed_status()[0]['last_success_article_count'] is None
    repo.save_collection([], [observation(feed, offset=1, count=0)])
    assert repo.feed_status()[0]['status'] == 'success'
    assert repo.feed_status()[0]['last_success_article_count'] == 0
    assert not repo.is_cache_valid()


def test_articles_and_observations_commit_atomically(tmp_path):
    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    feed = Feed(name='Source', url='https://example.com/feed')
    article = Article(title='New', source='Source', summary='', url='https://example.com/new')
    with pytest.raises(TypeError):
        repo.save_collection([article], [observation(feed, warnings=[object()])])
    assert repo.load() == []
    assert repo.feed_status() == []
    assert not repo.is_cache_valid()


def test_schema_v1_migration_preserves_articles_and_metadata(tmp_path):
    database = tmp_path / 'archive.sqlite3'
    article = Article(title='Existing', source='Source', summary='', url='https://example.com/old')
    with sqlite3.connect(database) as connection:
        connection.executescript('''
            CREATE TABLE articles (id TEXT PRIMARY KEY, payload TEXT NOT NULL,
                published TEXT, source TEXT NOT NULL, category TEXT, tags TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            PRAGMA user_version=1;
        ''')
        connection.execute('INSERT INTO articles VALUES (?, ?, NULL, ?, NULL, ?, ?, ?)',
                           (article_key(article), json.dumps(article_to_dict(article)),
                            'source', '[]', '2026-01-01', '2026-01-01'))
        connection.execute("INSERT INTO metadata VALUES ('legacy_json_imported', 'old-cache')")
    repo = SQLiteArticleRepository(database)
    assert repo.load() == [article]
    assert repo.feed_status() == []
    with sqlite3.connect(database) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == SQLITE_SCHEMA_VERSION
        assert connection.execute("SELECT value FROM metadata WHERE key='legacy_json_imported'").fetchone()[0] == 'old-cache'
