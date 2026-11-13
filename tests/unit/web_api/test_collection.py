from threading import Event
from types import SimpleNamespace
import time

from fastapi.testclient import TestClient
import pytest

from app.worker import collector_lock
from services.models import UpdateResult
from web_api.app import create_app
from web_api.security import SecuritySettings, create_credentials

HEADERS = {'X-Cyber-RSS-Request': '1'}


def wait_finished(client):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        response = client.get('/collection')
        if response.status_code == 429:
            time.sleep(float(response.headers.get('Retry-After', '1')))
            continue
        assert response.status_code == 200, response.text
        state = response.json()
        if state['status'] != 'running':
            return state
        time.sleep(.01)
    pytest.fail('Collection did not finish')


def test_manual_collection_is_nonblocking_and_excludes_duplicates(tmp_path):
    entered, release = Event(), Event()
    calls = []
    async def update(*, force_refresh):
        calls.append(force_refresh)
        entered.set()
        assert release.wait(5)
        return UpdateResult(2, 7, 6, False, 1)
    database = tmp_path / 'archive.sqlite3'
    with TestClient(create_app(database_file=database, collection_service_factory=lambda: SimpleNamespace(update=update))) as client:
        try:
            response = client.post('/collection', headers=HEADERS, json={'force_refresh': True})
            assert response.status_code == 202
            assert entered.wait(2)
            assert client.get('/health').json() == {'status': 'ok'}
            assert client.get('/articles').status_code == 200
            assert client.get('/collection').json()['status'] == 'running'
            assert client.post('/collection', headers=HEADERS, json={}).status_code == 409
            with pytest.raises(RuntimeError):
                with collector_lock(database):
                    pass
        finally:
            release.set()
        state = wait_finished(client)
        assert state['status'] == 'completed'
        assert state['result'] == {'feeds_downloaded': 2, 'articles_parsed': 7,
                                   'articles_saved': 6, 'cache_used': False, 'feeds_failed': 1, 'articles_pruned': 0}
        assert state['completed_at']
        assert calls == [True]
        with collector_lock(database):
            pass


def test_worker_lock_rejects_manual_collection_until_released(tmp_path):
    database = tmp_path / 'archive.sqlite3'
    async def update(*, force_refresh):
        return UpdateResult(0, 3, 3, True)
    with TestClient(create_app(database_file=database, collection_service_factory=lambda: SimpleNamespace(update=update))) as client:
        with collector_lock(database):
            state = client.get('/collection').json()
            assert state['status'] == 'running' and state['source'] == 'worker'
            assert client.post('/collection', headers=HEADERS, json={}).status_code == 409
        assert client.post('/collection', headers=HEADERS, json={'force_refresh': False}).status_code == 202
        assert wait_finished(client)['result']['cache_used'] is True


def test_collection_failure_releases_lock_and_allows_retry(tmp_path):
    database = tmp_path / 'archive.sqlite3'
    async def update(*, force_refresh):
        raise ValueError('private implementation detail')
    with TestClient(create_app(database_file=database, collection_service_factory=lambda: SimpleNamespace(update=update))) as client:
        for _ in range(2):
            assert client.post('/collection', headers=HEADERS, json={}).status_code == 202
            state = wait_finished(client)
            assert state['status'] == 'failed'
            assert 'private implementation detail' not in state['error']
            with collector_lock(database):
                pass


def test_collection_requires_intent_header_and_valid_input(tmp_path):
    with TestClient(create_app(database_file=tmp_path / 'archive.sqlite3')) as client:
        assert client.post('/collection', json={}).status_code == 403
        assert client.post('/collection', headers={**HEADERS, 'Sec-Fetch-Site': 'cross-site'}, json={}).status_code == 403
        assert client.options('/collection', headers={'Origin': 'https://evil.example',
                   'Access-Control-Request-Method': 'POST',
                   'Access-Control-Request-Headers': 'x-cyber-rss-request'}).status_code == 405
        assert client.post('/collection', headers=HEADERS, json={'force_refresh': 'false'}).status_code == 422
        assert client.post('/collection', headers=HEADERS, json={'command': 'arbitrary'}).status_code == 422
        assert client.get('/collection').headers['cache-control'] == 'no-store'


def test_collection_uses_existing_authentication(tmp_path):
    settings = SecuritySettings(credentials=create_credentials('reader', 'a-secure-test-password'))
    with TestClient(create_app(database_file=tmp_path / 'archive.sqlite3', security=settings), base_url='https://testserver') as client:
        assert client.get('/collection').status_code == 401
        assert client.post('/collection', headers=HEADERS, json={}).status_code == 401
        assert client.get('/collection', auth=('reader', 'a-secure-test-password')).status_code == 200


def test_manual_collection_downloads_and_persists_with_real_pipeline(tmp_path, monkeypatch):
    # The test feeds are served from a loopback server, which requires the opt-in.
    monkeypatch.setenv('CYBER_RSS_ALLOW_PRIVATE_FEEDS', '1')
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from app.container import ApplicationContainer

    class FeedServer(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(404 if self.path == '/missing' else 200)
            self.end_headers()
            self.wfile.write(b'''<?xml version="1.0"?><rss version="2.0"><channel>
                <title>Local source</title><link>https://example.com</link>
                <description>Test feed</description><item><title>Ransomware report</title>
                <link>https://example.com/report</link><description>CVE-2026-1234 investigation</description>
                </item></channel></rss>''')
        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), FeedServer)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = tmp_path / 'feeds'
    config.mkdir()
    port = server.server_port
    (config / 'news.yaml').write_text(f'''category: news
feeds:
  - name: Local source
    url: http://127.0.0.1:{port}/rss
    enabled: true
  - name: Broken source
    url: http://127.0.0.1:{port}/missing
    enabled: true
''')
    database = tmp_path / 'archive.sqlite3'
    def factory():
        container = ApplicationContainer(database_file=database, config_directory=config, misp_auto_update=False)
        container.fetcher.client.retries = 1
        return container.article_service
    try:
        with TestClient(create_app(database_file=database, collection_service_factory=factory,
                                  security=SecuritySettings(per_minute=10000, burst=10000,
                                                            global_per_minute=10000, global_burst=10000))) as client:
            assert client.post('/collection', headers=HEADERS, json={}).status_code == 202
            state = wait_finished(client)
            assert state['status'] == 'completed'
            assert state['result']['feeds_failed'] == 1
            assert state['result']['articles_saved'] == 1
            articles = client.get('/articles').json()['items']
            assert articles[0]['title'] == 'Ransomware report'
            assert {'type': 'cve', 'value': 'CVE-2026-1234'} in articles[0]['iocs']
            assert client.get('/feeds').json()['summary']['error'] == 1
            assert client.post('/collection', headers=HEADERS, json={}).status_code == 202
            assert wait_finished(client)['status'] == 'completed'
            assert client.get('/filters').json()['total'] == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
