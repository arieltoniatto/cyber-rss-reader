from datetime import datetime, timezone

from fastapi.testclient import TestClient

from parser.models import Article
from storage.sqlite_storage import SQLiteArticleRepository
from web_api.app import create_app
from config.models import Feed
from feeds.models import FeedObservation


def test_read_api_paginates_and_preserves_enrichment(tmp_path):
    repository = SQLiteArticleRepository(tmp_path / "archive.sqlite3")
    repository.refresh([Article(title=f"Malware report {i}", source="Source", summary="ransomware campaign",
                                url=f"https://example.com/{i}", category="News", tags=["Malware"],
                                malware=["BlackEnergy"], published=datetime(2026, 1, i + 1, tzinfo=timezone.utc))
                        for i in range(3)])
    with TestClient(create_app(repository)) as client:
        assert client.get("/health").json() == {"status": "ok"}
        first = client.get("/articles?limit=1&category=news&tag=malware").json()
        assert first["items"][0]["title"] == "Malware report 2"
        assert first["items"][0]["malware"] == ["BlackEnergy"]
        assert first["has_more"]
        second = client.get("/articles?limit=1&offset=1").json()
        assert second["items"][0]["id"] != first["items"][0]["id"]
        assert client.get("/articles?source=Unknown").json()["items"] == []
        assert len(client.get("/search?q=malware&limit=1&offset=1").json()["items"]) == 1
        assert client.get("/topics?limit=2").status_code == 200
        assert client.get("/articles?limit=0").status_code == 422
        assert client.get("/articles?offset=-1").status_code == 422
        assert client.get("/search?q=").status_code == 422
        assert client.post("/articles").status_code == 405


def test_empty_archive_returns_empty_results(tmp_path):
    with TestClient(create_app(database_file=tmp_path / "empty.sqlite3")) as client:
        assert client.get("/articles").json()["items"] == []
        assert client.get("/topics").json()["items"] == []


def test_feed_status_api_filters_and_paginates(tmp_path):
    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    now = datetime.now(timezone.utc)
    repo.save_collection([], [
        FeedObservation(feed=Feed(name='Good', url='https://example.com/good'),
                        attempted_at=now, completed_at=now, article_count=10),
        FeedObservation(feed=Feed(name='Bad', url='https://example.com/bad'),
                        attempted_at=now, completed_at=now, error='HTTP 404'),
    ])
    with TestClient(create_app(repo)) as client:
        page = client.get('/feeds?status=error&limit=1').json()
        assert page['summary'] == {'total': 2, 'collecting': 0, 'success': 1, 'error': 1}
        assert page['items'][0]['name'] == 'Bad'
        assert page['items'][0]['last_error'] == 'HTTP 404'
        assert page['items'][0]['last_success'] is None
        assert client.get('/feeds?limit=1').json()['has_more']
        assert not client.get('/feeds?limit=1&offset=1').json()['has_more']
        assert client.get('/feeds?status=unknown').status_code == 422


def test_frontend_filters_detail_and_tagged_search(tmp_path):
    from parser.models import IOC, IOCType

    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    article = Article(title='Malware report', source='Old source', category='news',
                      url='https://example.com/report?Case=A', summary='<script>alert(1)</script>',
                      tags=['Ransomware'], malware=['BlackEnergy'], threat_actors=['APT28'],
                      iocs=[IOC(IOCType.CVE, 'CVE-2026-1234')])
    repo.save([article, Article(title='Malware news', source='Another source', category='malware',
                               summary='', url='https://example.com/other')])
    with TestClient(create_app(repo)) as client:
        index = client.get('/')
        assert index.status_code == 200
        assert '<html lang="pt-BR">' in index.text
        assert "script-src 'self'" in index.headers['content-security-policy']
        assert client.get('/assets/app.js').status_code == 200
        assert client.get('/assets/app.css').status_code == 200
        filters = client.get('/filters').json()
        assert filters['total'] == 2
        assert {'value': 'Old source', 'count': 1} in filters['sources']
        assert {'value': 'Ransomware', 'count': 1} in filters['tags']
        search = client.get('/search', params={'q': 'malware', 'tag': 'ransomware'}).json()
        assert len(search['items']) == 1
        detail = client.get('/articles/detail', params={'id': search['items'][0]['id']}).json()
        assert detail['summary'] == article.summary
        assert detail['malware'] == ['BlackEnergy']
        assert detail['iocs'][0]['type'] == 'cve'
        assert client.get('/articles/detail', params={'id': 'missing'}).status_code == 404


def test_result_controls_filter_then_sort_then_paginate(tmp_path):
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    repo.save([Article(title=f'Ransomware report {i}', source='Source', category='news',
                       summary='', url=f'https://example.com/{i}', tags=['research'],
                       published=now - timedelta(days=i)) for i in range(10)])
    with TestClient(create_app(repo)) as client:
        for endpoint in ('/articles', '/search'):
            params = {'q': 'ransomware', 'order': 'oldest', 'period': 'week',
                      'tag': 'research', 'limit': 2, 'match': 'exact'}
            first = client.get(endpoint, params=params).json()
            assert [a['title'] for a in first['items']] == ['Ransomware report 6', 'Ransomware report 5']
            assert first['has_more']
            second = client.get(endpoint, params={**params, 'offset': 2}).json()
            assert [a['title'] for a in second['items']] == ['Ransomware report 4', 'Ransomware report 3']
            final = client.get(endpoint, params={**params, 'offset': 6}).json()
            assert [a['title'] for a in final['items']] == ['Ransomware report 0']
            assert not final['has_more']
            assert len(client.get(endpoint, params={**params, 'period': 'today'}).json()['items']) == 1
            for bad in ({'limit': 0}, {'limit': 101}, {'offset': -1}, {'order': 'unknown'}, {'period': 'unknown'}):
                assert client.get(endpoint, params={**params, **bad}).status_code == 422
        assert client.get('/search', params={'q': 'ransmware', 'fuzzy_threshold': 70}).json()['items']
        assert not client.get('/search', params={'q': 'ransmware', 'match': 'exact'}).json()['items']
        assert not client.get('/search', params={'q': 'ransmware', 'fuzzy_threshold': 100}).json()['items']
        for bad in ({'match': 'unknown'}, {'fuzzy_threshold': -1}, {'fuzzy_threshold': 101}, {'offset': 10001}):
            assert client.get('/search', params={'q': 'malware', **bad}).status_code == 422


def test_attack_detail_resolves_legacy_articles_and_preserves_provenance(tmp_path):
    from parser.models import AttackMapping

    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    repo.save([Article(title='Technique T1059.001', source='Source', summary='Campaign C0001',
                       url='https://example.com/attack', malware=['BlackEnergy'], threat_actors=['APT28'])])
    with TestClient(create_app(repo)) as client:
        row = client.get('/articles').json()['items'][0]
        assert row['attack'] is None
        detail = client.get('/articles/detail', params={'id': row['id']}).json()
        assert 'T1059.001' in detail['attack']['technique_ids']
        assert detail['attack']['catalog_version'] == '19.1'
        assert detail['attack_details']['status'] == 'ok'
        techniques = detail['attack_details']['techniques']
        assert next(n for n in techniques if n['id'] == 'T1059.001')['basis'] == 'article'
        assert any(n['basis'] == 'catalog' for n in techniques)
        assert all(edge['basis'] == 'catalog' for edge in detail['attack_details']['relationships'])
        assert repo.load()[0].attack is None
    repo.save([Article(title='Old mapping', source='Source', summary='', url='https://example.com/old',
                       attack=AttackMapping('older', entity_ids=['T1059']))])
    with TestClient(create_app(repo)) as client:
        rows = client.get('/articles').json()['items']
        old = next(row for row in rows if row['title'] == 'Old mapping')
        detail = client.get('/articles/detail', params={'id': old['id']}).json()
        assert detail['attack_details']['status'] == 'version_mismatch'
        assert detail['attack']['entity_ids'] == ['T1059']
        assert not detail['attack_details']['relationships']
    with TestClient(create_app(repo, attack_catalog_file=tmp_path / 'missing.json')) as client:
        assert client.get('/health').status_code == 200
        assert client.get('/articles/detail', params={'id': old['id']}).json()['attack_details']['status'] == 'unavailable'
