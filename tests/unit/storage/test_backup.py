from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

import pytest

from config.models import Feed
from feeds.models import FeedObservation
from parser.models import Article
from storage.backup import create_backup, restore_backup
from storage.sqlite_storage import SQLiteArticleRepository


def archive(tmp_path):
    path = tmp_path / 'archive #1.sqlite3'
    repo = SQLiteArticleRepository(path)
    now = datetime.now(timezone.utc)
    repo.save_collection([Article(title='Existing', source='Source', summary='',
                                 url='https://example.com/1', malware=['BlackEnergy'])],
                         [FeedObservation(feed=Feed(name='Source', url='https://example.com/feed'),
                                          attempted_at=now, completed_at=now, article_count=1)])
    return path, repo


def test_online_backup_includes_wal_and_restores_articles_and_feed_state(tmp_path):
    database, repo = archive(tmp_path)
    # Keep a connection open so new commits remain in the source WAL.
    with sqlite3.connect(database) as writer:
        writer.execute('PRAGMA wal_autocheckpoint=0')
        writer.execute('SELECT COUNT(*) FROM articles').fetchone()
        repo.save([Article(title='New', source='Source', summary='', url='https://example.com/2')])
        assert Path(str(database) + '-wal').stat().st_size > 0
        backup = create_backup(database, tmp_path / 'backups')
        restored = restore_backup(backup, tmp_path / 'restored.sqlite3')
        manifest = json.loads(backup.with_suffix('.json').read_text())
        assert manifest['articles'] == 2
        assert manifest['feeds'] == 1
        assert backup.stat().st_mode & 0o777 == 0o600
        assert not Path(str(backup) + '-wal').exists()
        assert SQLiteArticleRepository(restored).load() == repo.load()
        assert SQLiteArticleRepository(restored).feed_status() == repo.feed_status()


def test_retention_only_prunes_complete_owned_snapshots(tmp_path):
    database, _ = archive(tmp_path)
    directory = tmp_path / 'backups'
    first = create_backup(database, directory, keep=2)
    (directory / 'articles-unrelated.sqlite3').write_text('Keep this file')
    second = create_backup(database, directory, keep=2)
    third = create_backup(database, directory, keep=2)
    assert not first.exists()
    assert not first.with_suffix('.json').exists()
    assert second.exists() and third.exists()
    assert (directory / 'articles-unrelated.sqlite3').read_text() == 'Keep this file'


def test_failed_backup_does_not_prune_existing_snapshots(tmp_path):
    database, _ = archive(tmp_path)
    previous = create_backup(database, tmp_path / 'backups', keep=1)
    database.write_bytes(b'Invalid database')
    with pytest.raises(sqlite3.DatabaseError):
        create_backup(database, tmp_path / 'backups', keep=1)
    assert previous.exists()
    assert previous.with_suffix('.json').exists()
    assert list((tmp_path / 'backups').glob('.pending-*')) == []


def test_restore_rejects_tampering_and_existing_destination(tmp_path):
    database, _ = archive(tmp_path)
    backup = create_backup(database, tmp_path / 'backups')
    original = database.read_bytes()
    with pytest.raises(FileExistsError):
        restore_backup(backup, database)
    assert database.read_bytes() == original
    with backup.open('ab') as stream:
        stream.write(b'tampered')
    with pytest.raises(ValueError, match='checksum'):
        restore_backup(backup, tmp_path / 'restored.sqlite3')
    assert not (tmp_path / 'restored.sqlite3').exists()


def test_missing_source_and_invalid_retention_do_not_create_archives(tmp_path):
    with pytest.raises(FileNotFoundError):
        create_backup(tmp_path / 'missing.sqlite3', tmp_path / 'backups')
    database, _ = archive(tmp_path)
    with pytest.raises(ValueError):
        create_backup(database, tmp_path / 'backups', keep=0)
    assert not (tmp_path / 'backups').exists()
