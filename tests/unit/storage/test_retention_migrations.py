from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest

from config.models import Feed
from feeds.models import FeedObservation
from parser.models import Article
from storage.factory import create_repository
from storage.maintenance import preview_retention, sqlite_status
from storage.migrations import Migration, SQLITE_MIGRATIONS, migrate_sqlite
from storage.retention import RetentionPolicy, prune
from storage.sqlite_storage import SQLiteArticleRepository
from storage.utils import article_key


def article(index):
    return Article(title=str(index), source='Source', summary='Report', url=f'https://example.com/{index}')


def test_age_then_cap_preserves_recent_observations_and_metadata(tmp_path):
    path = tmp_path / 'archive.sqlite3'
    repo = SQLiteArticleRepository(path)
    repo.save([replace(article(i), published=datetime(2000, 1, 1, tzinfo=timezone.utc)) for i in range(5)])
    now = datetime.now(timezone.utc)
    with repo._connection() as connection:
        for i, age in enumerate([100, 40, 3, 2, 1]):
            connection.execute('UPDATE articles SET last_seen=? WHERE id=?', ((now-timedelta(days=age)).isoformat(), article_key(article(i))))
        connection.execute("INSERT INTO metadata VALUES ('preserved','value')")
        preview = prune(connection, RetentionPolicy(30, 2), backend='sqlite', dry_run=True, now=now)
    assert (preview.before, preview.expired, preview.over_limit, preview.remaining, preview.deleted) == (5, 2, 1, 2, 0)
    assert len(repo.load()) == 5
    result = repo.prune(RetentionPolicy(30, 2), dry_run=False)
    assert result.deleted == 3
    assert {a.title for a in repo.load()} == {'3', '4'}
    with repo._connection() as connection:
        assert connection.execute("SELECT value FROM metadata WHERE key='preserved'").fetchone()[0] == 'value'
        assert json.loads(connection.execute("SELECT value FROM metadata WHERE key='last_retention'").fetchone()[0])['deleted'] == 3


def test_automatic_retention_skips_failures_and_runs_on_empty_success(tmp_path):
    repo = SQLiteArticleRepository(tmp_path/'archive.sqlite3', retention=RetentionPolicy(max_articles=1))
    repo.save([article(0), article(1)])  # Explicit save/import must not prune.
    feed = Feed(name='Source', url='https://example.com/rss', category='news')
    now = datetime.now(timezone.utc)
    failed = FeedObservation(feed=feed, attempted_at=now, completed_at=now, error='Offline')
    assert repo.save_collection([], [failed]) is None
    assert len(repo.load()) == 2
    successful = FeedObservation(feed=feed, attempted_at=now+timedelta(seconds=1), completed_at=now+timedelta(seconds=1), article_count=0)
    assert repo.save_collection([], [successful]).deleted == 1
    assert len(repo.load()) == 1
    assert repo.feed_status()[0]['status'] == 'success'


def test_disabled_policy_and_invalid_environment(tmp_path, monkeypatch):
    path = tmp_path/'archive.sqlite3'
    repo = SQLiteArticleRepository(path)
    repo.refresh([article(i) for i in range(10)])
    assert repo.prune().deleted == 0 and len(repo.load()) == 10
    monkeypatch.setenv('CYBER_RSS_RETENTION_DAYS', '-1')
    with pytest.raises(ValueError, match='Invalid CYBER_RSS'):
        create_repository(database_file=tmp_path/'invalid.sqlite3')
    assert not (tmp_path/'invalid.sqlite3').exists()
    for kwargs in [{'days': True}, {'max_articles': -1}, {'days': 36501}]:
        with pytest.raises(ValueError):
            RetentionPolicy(**kwargs)


def test_readonly_inspection_does_not_create_or_migrate_database(tmp_path):
    path = tmp_path/'archive.sqlite3'
    assert sqlite_status(path)['current_version'] == 0
    assert preview_retention(RetentionPolicy(30), database_file=path).before == 0
    assert not path.exists()
    with sqlite3.connect(path) as connection:
        migrate_sqlite(connection, SQLITE_MIGRATIONS[:2])
        connection.execute('DROP TABLE schema_migrations')
    original = path.read_bytes()
    assert sqlite_status(path)['current_version'] == 2
    assert preview_retention(RetentionPolicy(30), database_file=path).before == 0
    assert path.read_bytes() == original
    SQLiteArticleRepository(path)
    report = sqlite_status(path)
    assert report['current_version'] == 3 and not report['pending']
    assert [row['adopted'] for row in report['history']] == [True, True, False]


def test_migration_rollback_checksum_and_idempotency(tmp_path):
    path = tmp_path/'archive.sqlite3'
    SQLiteArticleRepository(path).save([article(0)])
    with sqlite3.connect(path) as connection:
        assert migrate_sqlite(connection) == []
        bad = Migration(4, 'broken', ('CREATE TABLE rollback_marker (value TEXT)', 'INVALID SQL'))
        with pytest.raises(sqlite3.OperationalError):
            migrate_sqlite(connection, (*SQLITE_MIGRATIONS, bad))
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 3
        assert not connection.execute("SELECT 1 FROM sqlite_master WHERE name='rollback_marker'").fetchone()
        assert connection.execute('SELECT COUNT(*) FROM schema_migrations').fetchone()[0] == 3
        connection.execute("UPDATE schema_migrations SET checksum='tampered' WHERE version=1")
    with pytest.raises(ValueError, match='checksum mismatch'):
        SQLiteArticleRepository(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute('SELECT COUNT(*) FROM articles').fetchone()[0] == 1


def test_commands_preview_apply_and_upgrade_backup(tmp_path, monkeypatch, capsys):
    from tools.retention import main as retain
    from tools.migrate_database import main as migrate
    path = tmp_path/'archive.sqlite3'
    monkeypatch.delenv('CYBER_RSS_DATABASE_URL', raising=False)
    monkeypatch.delenv('CYBER_RSS_DATABASE_URL_FILE', raising=False)
    with sqlite3.connect(path) as connection:
        migrate_sqlite(connection, SQLITE_MIGRATIONS[:2])
        connection.execute('DROP TABLE schema_migrations')
    monkeypatch.setattr('sys.argv', ['rss-migrate', '--database', str(path)])
    migrate()
    assert json.loads(capsys.readouterr().out)['current_version'] == 2
    monkeypatch.setattr('sys.argv', ['rss-migrate', '--database', str(path), '--upgrade'])
    migrate()
    report = json.loads(capsys.readouterr().out)
    assert report['current_version'] == 3 and report['backup']
    with sqlite3.connect(report['backup']) as connection:
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 2
    repo = SQLiteArticleRepository(path)
    repo.save([article(i) for i in range(3)])
    args = ['rss-retention', '--database', str(path), '--max-articles', '1']
    monkeypatch.setattr('sys.argv', args)
    retain()
    assert json.loads(capsys.readouterr().out)['would_delete'] == 2
    assert len(repo.load()) == 3
    monkeypatch.setattr('sys.argv', [*args, '--apply'])
    retain()
    assert json.loads(capsys.readouterr().out)['deleted'] == 2
    assert len(repo.load()) == 1


@pytest.mark.parametrize('deleted', ['version=2', '1=1'])
def test_incomplete_journal_is_rejected(tmp_path, deleted):
    path = tmp_path/'archive.sqlite3'
    SQLiteArticleRepository(path)
    with sqlite3.connect(path) as connection:
        connection.execute(f'DELETE FROM schema_migrations WHERE {deleted}')
    with pytest.raises(ValueError, match='incomplete'):
        sqlite_status(path)
    with pytest.raises(ValueError, match='incomplete'):
        SQLiteArticleRepository(path)
