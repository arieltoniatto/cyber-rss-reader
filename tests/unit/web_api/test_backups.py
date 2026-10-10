from io import BytesIO
from threading import Event
from zipfile import ZipFile
import time

from fastapi.testclient import TestClient
import pytest

from config.feed_registry import FeedRegistry
from parser.models import Article
from storage.backup import create_backup, restore_backup
from storage.sqlite_storage import SQLiteArticleRepository
from web_api.app import create_app
from web_api.backups import BackupController, BackupBusy
from web_api.security import SecuritySettings, create_credentials

HEADERS = {'X-Cyber-RSS-Request': '1'}


def finished(client):
    for _ in range(300):
        state = client.get('/backups/status').json()
        if state['status'] != 'running':
            return state
        time.sleep(.01)
    pytest.fail('Backup did not finish')


def test_create_list_download_restore_and_restart(tmp_path, monkeypatch):
    database = tmp_path / 'archive.sqlite3'
    directory = tmp_path / 'backups'
    repo = SQLiteArticleRepository(database)
    repo.save([Article(title='Article', source='Source', summary='A summary', url='https://example.com/article')])
    feeds = tmp_path / 'feeds'
    feeds.mkdir()
    (feeds / 'news.yaml').write_text('category: news\nfeeds: []\n')
    FeedRegistry(database, feeds).save({'name': 'Managed source', 'url': 'https://example.com/feed',
                                       'enabled': False, 'description': None, 'category': 'news'})
    import web_api.app as app_module
    from storage.backup import export_backup
    temporary = []
    def export(*args):
        path = export_backup(*args)
        temporary.append(path)
        return path
    monkeypatch.setattr(app_module, 'export_backup', export)
    with TestClient(create_app(repo, backup_directory=directory)) as client:
        assert client.get('/backups').json()['items'] == []
        assert client.post('/backups', headers=HEADERS).status_code == 202
        assert finished(client)['status'] == 'completed'
        items = client.get('/backups').json()['items']
        assert len(items) == 1 and items[0]['articles'] == 1
        assert items[0]['downloadable'] is True and items[0]['size_bytes'] > 0
        response = client.get('/backups/' + items[0]['id'] + '/download')
        assert response.status_code == 200
        assert response.headers['content-type'] == 'application/zip'
        assert response.headers['cache-control'] == 'no-store'
        assert all(not path.exists() for path in temporary)
        exported = tmp_path / 'downloaded'
        with ZipFile(BytesIO(response.content)) as bundle:
            assert len(bundle.namelist()) == 2
            bundle.extractall(exported)
        restored = restore_backup(exported / items[0]['id'], tmp_path / 'restored.sqlite3')
        assert SQLiteArticleRepository(restored).load() == repo.load()
        assert FeedRegistry(restored, feeds).list()[0]['name'] == 'Managed source'
    with TestClient(create_app(database_file=database, backup_directory=directory)) as client:
        assert len(client.get('/backups').json()['items']) == 1
        assert client.get('/backups/status').json()['status'] == 'idle'


def test_background_job_duplicate_rejection_and_retry(tmp_path):
    started, release = Event(), Event()
    calls = []
    def creator(*args, **kwargs):
        calls.append(1)
        started.set()
        assert release.wait(5)
        if len(calls) == 1:
            raise ValueError('private diagnostic')
        return tmp_path / 'snapshot.sqlite3'
    controller = BackupController(tmp_path / 'db', tmp_path / 'backups', creator=creator)
    try:
        assert controller.start()['status'] == 'running'
        assert started.wait(2)
        with pytest.raises(BackupBusy):
            controller.start()
        release.set()
        for _ in range(100):
            if controller.status()['status'] != 'running':
                break
            time.sleep(.01)
        assert controller.status()['status'] == 'failed'
        assert 'private diagnostic' not in controller.status()['error']
        controller.start()
    finally:
        release.set()
        controller.close()
    assert controller.status()['status'] == 'completed'


def test_download_rejects_missing_tampered_and_symlinked_backups(tmp_path):
    database = tmp_path / 'archive.sqlite3'
    directory = tmp_path / 'backups'
    SQLiteArticleRepository(database)
    backup = create_backup(database, directory)
    with TestClient(create_app(database_file=database, backup_directory=directory)) as client:
        for name in ('unknown', '..', 'archive.sqlite3', 'articles-unrelated.sqlite3'):
            assert client.get('/backups/' + name + '/download').status_code == 404
        with backup.open('ab') as stream:
            stream.write(b'tampered')
        assert client.get('/backups/' + backup.name + '/download').status_code == 409
        backup.unlink()
        backup.symlink_to(database)
        assert client.get('/backups/' + backup.name + '/download').status_code == 404
        assert client.get('/backups').json()['items'] == []
        backup.unlink()
    backup = create_backup(database, directory)
    backup.with_suffix('.json').write_text('invalid json')
    with TestClient(create_app(database_file=database, backup_directory=directory)) as client:
        item = client.get('/backups').json()['items'][0]
        assert item['downloadable'] is False
        assert 'error' in item
        assert client.get('/backups/' + backup.name + '/download').status_code == 409


def test_backup_actions_and_downloads_use_existing_security(tmp_path):
    app = create_app(database_file=tmp_path / 'archive.sqlite3', backup_directory=tmp_path / 'backups')
    with TestClient(app) as client:
        assert client.post('/backups').status_code == 403
        assert client.post('/backups', headers={**HEADERS, 'Sec-Fetch-Site': 'cross-site'}).status_code == 403
    settings = SecuritySettings(credentials=create_credentials('reader', 'a-secure-test-password'))
    with TestClient(create_app(database_file=tmp_path / 'archive.sqlite3', security=settings),
                    base_url='https://testserver') as client:
        for path in ('/backups', '/backups/status', '/backups/unknown/download'):
            assert client.get(path).status_code == 401
        assert client.post('/backups', headers=HEADERS).status_code == 401
        assert client.get('/backups', auth=('reader', 'a-secure-test-password')).status_code == 200


def test_api_backup_is_nonblocking_and_rejects_duplicate_requests(tmp_path):
    from app.worker import collector_lock
    database = tmp_path / 'archive.sqlite3'
    directory = tmp_path / 'backups'
    started, release = Event(), Event()
    def slow(database, directory, *, keep):
        started.set()
        assert release.wait(5)
        return create_backup(database, directory, keep=keep)
    app = create_app(database_file=database, backup_directory=directory)
    with TestClient(app) as client:
        app.state.backups.creator = slow
        try:
            with collector_lock(database):
                assert client.post('/backups', headers=HEADERS).status_code == 202
                assert started.wait(2)
                assert client.get('/backups/status').json()['status'] == 'running'
                assert client.get('/health').status_code == 200
                assert client.post('/backups', headers=HEADERS).status_code == 409
        finally:
            release.set()
        assert finished(client)['status'] == 'completed'


@pytest.mark.asyncio
async def test_temporary_bundle_removed_after_send_failure(tmp_path):
    from web_api.backups import BackupDownloadResponse
    bundle = tmp_path / 'download.zip'
    bundle.write_bytes(b'temporary bundle')
    response = BackupDownloadResponse(bundle, media_type='application/zip')
    async def receive():
        return {'type': 'http.request'}
    async def send(message):
        raise OSError('simulated disconnected client')
    with pytest.raises(OSError):
        await response({'type': 'http', 'method': 'GET', 'headers': [],
                        'asgi': {'spec_version': '2.4'}}, receive, send)
    assert not bundle.exists()
