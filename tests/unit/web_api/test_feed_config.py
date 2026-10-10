from pathlib import Path
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient
import pytest

from app.container import ApplicationContainer
from app.worker import collector_lock
from config.feed_registry import FeedRegistry
from parser.models import Article
from storage.backup import create_backup, restore_backup
from storage.sqlite_storage import SQLiteArticleRepository
from web_api.app import create_app

HEADERS = {'X-Cyber-RSS-Request': '1'}


@pytest.fixture
def settings(tmp_path):
    directory = tmp_path / 'feeds'
    directory.mkdir()
    (directory / 'news.yaml').write_text('''category: news
feeds:
  - name: Active source
    url: https://example.com/feed
  - name: Disabled source
    url: https://example.com/disabled
    enabled: false
''')
    return tmp_path / 'archive.sqlite3', directory


def value(**overrides):
    return {'name': 'New source', 'url': 'https://example.com/new', 'category': 'news',
            'description': 'A source', 'enabled': True, **overrides}


def test_add_edit_toggle_persist_and_preserve_history(settings):
    database, directory = settings
    repo = SQLiteArticleRepository(database)
    repo.refresh([Article(title='Old article', source='Active source', summary='Archived content', url='https://example.com/article')])
    with TestClient(create_app(repo, feed_directory=directory)) as client:
        initial = client.get('/feed-config').json()
        assert initial['total'] == 2 and initial['enabled'] == 1
        assert next(row for row in initial['items'] if row['name'] == 'Disabled source')['enabled'] is False
        added = client.post('/feed-config', headers=HEADERS, json=value()).json()
        assert added['id']
        assert not repo.is_cache_valid()
        saved = client.put('/feed-config/' + added['id'], headers=HEADERS,
                           json=value(url='https://example.com/changed', enabled=False))
        assert saved.status_code == 200
        assert saved.json()['id'] == added['id'] and saved.json()['enabled'] is False
        assert client.get('/articles').json()['items'][0]['title'] == 'Old article'
    # Restart/recreate and changed templates must preserve the managed snapshot.
    (directory / 'news.yaml').write_text('category: news\nfeeds: []\n')
    with TestClient(create_app(database_file=database, feed_directory=directory)) as client:
        assert client.get('/feed-config').json()['total'] == 3
        assert next(row for row in client.get('/feed-config').json()['items'] if row['id'] == added['id'])['url'] == 'https://example.com/changed'


def test_validation_duplicates_and_collection_lock(settings):
    database, directory = settings
    with TestClient(create_app(database_file=database, feed_directory=directory)) as client:
        assert client.post('/feed-config', json=value()).status_code == 403
        assert client.post('/feed-config', headers={**HEADERS, 'Sec-Fetch-Site': 'cross-site'}, json=value()).status_code == 403
        for changes in ({'url': 'javascript:alert(1)'}, {'url': 'https://user:secret@example.com/feed'},
                        {'category': '../news'}, {'enabled': 'false'}, {'name': '   '}):
            assert client.post('/feed-config', headers=HEADERS, json=value(**changes)).status_code == 422
        for changes in ({'name': 'active source'}, {'url': 'https://example.com/feed'}):
            assert client.post('/feed-config', headers=HEADERS, json=value(**changes)).status_code == 409
        with collector_lock(database):
            assert client.post('/feed-config', headers=HEADERS, json=value()).status_code == 409
        assert client.get('/feed-config').json()['total'] == 2
        assert client.put('/feed-config/missing', headers=HEADERS, json=value()).status_code == 404


@pytest.mark.asyncio
async def test_existing_collector_reloads_configuration_before_next_cycle(settings):
    database, directory = settings
    container = ApplicationContainer(database_file=database, config_directory=directory, misp_auto_update=False)
    calls = []
    async def fetch():
        calls.append([feed.name for category in container.fetcher.configuration.categories for feed in category.feeds])
        return []
    container.fetcher.fetch_all = AsyncMock(side_effect=fetch)
    await container.article_service.update(force_refresh=True)
    registry = FeedRegistry(database, directory)
    rows = registry.list()
    for row in rows:
        feed_id = row.pop('id')
        registry.save({**row, 'enabled': row['name'] == 'Disabled source'}, feed_id=feed_id)
    await container.article_service.update(force_refresh=True)
    assert calls == [['Active source'], ['Disabled source']]


def test_backup_and_restore_include_managed_feeds(settings, tmp_path):
    database, directory = settings
    SQLiteArticleRepository(database)
    registry = FeedRegistry(database, directory)
    saved = registry.save(value())
    backup = create_backup(database, tmp_path / 'backups')
    restored = restore_backup(backup, tmp_path / 'restored.sqlite3')
    assert next(row for row in FeedRegistry(restored, directory).list() if row['id'] == saved['id']) == saved
