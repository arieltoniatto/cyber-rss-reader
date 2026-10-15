import json
from fastapi.testclient import TestClient

from parser.models import Article
from storage.sqlite_storage import SQLiteArticleRepository
from web_api.app import create_app


def test_download_exports_apply_filters_and_validate_limits(tmp_path):
    repo = SQLiteArticleRepository(tmp_path/'archive.sqlite3')
    repo.save([Article(title='Report', source='Research', summary='Complete feed text. '*100,
                       url='https://example.com/report', category='news', threat_actors=['APT28'])])
    with TestClient(create_app(repo)) as client:
        result = client.get('/exports/articles', params={'format': 'jsonl', 'threat_actor': 'apt28'})
        assert result.status_code == 200
        assert result.headers['content-disposition'] == 'attachment; filename="cyber-rss-articles.jsonl"'
        assert result.headers['cache-control'] == 'no-store'
        assert result.headers['x-export-count'] == '1'
        assert json.loads(result.text)['summary'] == repo.load()[0].summary
        assert client.get('/exports/articles?format=json&source=missing').json()['count'] == 0
        assert client.get('/exports/articles?format=csv').text.startswith('id,title,source,')
        for query in ['limit=10001', 'offset=-1', 'format=exe', 'ioc_type=unknown', 'ioc=%20']:
            assert client.get('/exports/articles?'+query).status_code == 422
        assert client.get('/alerts/status').json()['pending'] == 0
