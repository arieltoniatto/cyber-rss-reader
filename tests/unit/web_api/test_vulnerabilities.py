import httpx
from fastapi.testclient import TestClient

from parser.models import Article
from services.vulnerability_service import VulnerabilityService
from storage.sqlite_storage import SQLiteArticleRepository
from storage.utils import article_key
from web_api.app import create_app
from web_api.security import SecuritySettings, create_credentials


def test_old_article_offline_details_explicit_lookup_and_cache(tmp_path):
    payload = {'dataType': 'CVE_RECORD', 'cveMetadata': {'cveId': 'CVE-2021-44228', 'state': 'PUBLISHED'},
               'containers': {'cna': {'title': 'Log4j vulnerability', 'descriptions': [{'lang': 'en', 'value': 'Remote code execution'}]}}}
    calls = []
    lookup = VulnerabilityService(tmp_path / 'cve-cache.sqlite3', transport=httpx.MockTransport(
        lambda request: calls.append(request) or httpx.Response(200, json=payload)))
    repository = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    article = Article(title='Log4j', source='Source', summary='CVE-2021-44228', url='https://example.com/report')
    repository.save([article])
    with TestClient(create_app(repository, vulnerability_service=lookup)) as client:
        result = client.get('/articles/detail', params={'id': article_key(article)}).json()
        assert result['vulnerabilities'][0]['status'] == 'not_looked_up'
        assert calls == []
        assert client.get('/vulnerabilities/cve-2021-44228').json()['status'] == 'not_looked_up'
        assert client.post('/vulnerabilities/CVE-2021-44228', json={}).status_code == 403
        assert client.post('/vulnerabilities/CVE-2021-44228', json={},
                           headers={'X-Cyber-RSS-Request': '1', 'Sec-Fetch-Site': 'cross-site'}).status_code == 403
        headers = {'X-Cyber-RSS-Request': '1'}
        assert client.post('/vulnerabilities/invalid', headers=headers, json={}).status_code == 422
        assert client.post('/vulnerabilities/CVE-2021-44228', headers=headers, json={'refresh': 'yes'}).status_code == 422
        response = client.post('/vulnerabilities/CVE-2021-44228', headers=headers, json={})
        assert response.status_code == 200 and response.headers['cache-control'] == 'no-store'
        assert response.json()['record']['title'] == 'Log4j vulnerability'
        result = client.get('/articles/detail', params={'id': article_key(article)}).json()
        assert result['vulnerabilities'][0]['record']['cvss'] == []
        assert len(calls) == 1
        assert repository.get(article_key(article)) == article  # Read/lookup never rewrites history.
        assert client.post('/vulnerabilities/CVE-2021-44228', headers=headers, json={'refresh': True}).json()['status'] == 'rate_limited'
        assert client.get('/health').json() == {'status': 'ok'}


def test_cve_lookup_obeys_optional_authentication(tmp_path):
    calls = []
    lookup = VulnerabilityService(tmp_path / 'cache.sqlite3', transport=httpx.MockTransport(
        lambda request: calls.append(request) or httpx.Response(404)))
    credentials = create_credentials('user', 'long-secret-password')
    with TestClient(create_app(database_file=tmp_path / 'archive.sqlite3', vulnerability_service=lookup,
                              security=SecuritySettings(credentials=credentials)), base_url='https://testserver') as client:
        assert client.post('/vulnerabilities/CVE-2021-44228', json={}, headers={'X-Cyber-RSS-Request': '1'}).status_code == 401
        assert calls == []
        response = client.post('/vulnerabilities/CVE-2021-44228', json={}, headers={'X-Cyber-RSS-Request': '1'},
                               auth=('user', 'long-secret-password'))
        assert response.json()['status'] == 'not_found'
        assert len(calls) == 1


def test_remote_failure_does_not_break_article_or_archive(tmp_path):
    lookup = VulnerabilityService(tmp_path / 'cache.sqlite3', transport=httpx.MockTransport(
        lambda request: httpx.Response(503)))
    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    article = Article(title='Report CVE-2021-44228', summary='', source='Source', url='https://example.com/report')
    repo.save([article])
    with TestClient(create_app(repo, vulnerability_service=lookup)) as client:
        result = client.post('/vulnerabilities/CVE-2021-44228', json={}, headers={'X-Cyber-RSS-Request': '1'}).json()
        assert result['status'] == 'unavailable'
        detail = client.get('/articles/detail', params={'id': article_key(article)}).json()
        assert detail['title'] == article.title
        assert detail['vulnerabilities'][0]['status'] == 'unavailable'
        assert client.get('/articles').json()['items'][0]['title'] == article.title
