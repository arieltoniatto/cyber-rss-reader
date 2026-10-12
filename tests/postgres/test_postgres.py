"""Run against a dedicated test database via CYBER_RSS_TEST_POSTGRES_URL."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime,timedelta,timezone
import hashlib
import json
import os
from pathlib import Path
import time
from unittest.mock import AsyncMock

import pytest
pytest.importorskip('psycopg')
import psycopg
from fastapi.testclient import TestClient

from config.models import Feed
from config.postgres_feed_registry import PostgreSQLFeedRegistry
from config.feed_registry import FeedConflict,FeedNotFound,FeedRegistry
from feeds.models import FeedObservation,FeedResult
from parser.models import Article,IOC,IOCType,AttackMapping
from storage.postgres_storage import PostgreSQLArticleRepository
from storage.sqlite_storage import SQLiteArticleRepository
from storage.postgres_import import import_sqlite,sqlite_snapshot
from storage.locks import collector_lock,worker_instance_lock,CollectorBusy
from storage.utils import article_key
from web_api.app import create_app
from services.search_service import SearchService
from search.engine import SearchEngine

pytestmark=pytest.mark.postgres
URL=os.environ.get('CYBER_RSS_TEST_POSTGRES_URL')


@pytest.fixture
def repo():
    if not URL:
        pytest.skip('Set CYBER_RSS_TEST_POSTGRES_URL to a dedicated, disposable database')
    result=PostgreSQLArticleRepository(URL)
    with result._connection() as connection:
        connection.execute('TRUNCATE cyber_rss.articles,cyber_rss.feed_status')
        connection.execute("DELETE FROM cyber_rss.metadata WHERE key!='schema_version'")
    return result


def article(index=0,**kwargs):
    return Article(title=f'APT28 report {index}',source='Source',summary='CVE-2021-44228 investigation',
                   url=f'https://example.com/{index}',category='News',tags=['APT','Threat','APT'],
                   published=datetime(2026,10,10,tzinfo=timezone.utc)+timedelta(days=index),
                   malware=['BlackEnergy'],threat_actors=['APT28'],iocs=[IOC(IOCType.CVE,'CVE-2021-44228')],
                   attack=AttackMapping('19.1',['G0007','T1059.001'],['T1059.001']),cve_ids=['CVE-2021-44228'],**kwargs)


def test_roundtrip_history_dedup_metadata_and_cache(repo):
    first=article()
    repo.refresh([first,first])
    assert repo.load()==[first]
    assert repo.get(article_key(first))==first
    assert repo.is_cache_valid()
    with repo._connection() as connection:
        original=connection.execute('SELECT first_seen FROM cyber_rss.articles').fetchone()[0]
    changed=replace(first,title='Updated report')
    repo.refresh([changed,article(1)])
    assert repo.load()==[article(1),changed]
    with repo._connection() as connection:
        assert connection.execute('SELECT first_seen FROM cyber_rss.articles WHERE id=%s',(article_key(first),)).fetchone()[0]==original
    repo.refresh([])
    assert len(repo.load())==2
    repo.clear()
    assert repo.load()==[] and not repo.is_cache_valid()


def test_postgres_filter_pagination_null_dates_unicode_and_injection_match_sqlite(repo,tmp_path):
    sqlite=SQLiteArticleRepository(tmp_path/'archive.sqlite3')
    rows=[article(0),article(1),replace(article(2),published=None,source='Straße',tags=['Exploit']),
          replace(article(3),url='https://example.com/'+ 'x'*9000)]
    repo.save(rows);sqlite.save(rows)
    assert repo.load()==sqlite.load()
    assert repo.latest(category='news',tag='aPt',limit=1,offset=1)==sqlite.latest(category='news',tag='aPt',limit=1,offset=1)
    assert repo.latest(source='STRASSE')==sqlite.latest(source='STRASSE')
    assert repo.latest(source="Source' OR 1=1 --")==[]
    assert repo.get(article_key(rows[-1]))==rows[-1]
    assert repo.filters()==sqlite.filters()
    assert repo.get('missing') is None
    with pytest.raises(ValueError):repo.latest(limit=0)
    with pytest.raises(ValueError):repo.latest(offset=-1)


def test_feed_status_success_error_stale_outcome_and_transaction_rollback(repo):
    feed=Feed(name='Source',url='https://example.com/rss',category='news')
    now=datetime.now(timezone.utc)
    repo.begin_feed_collection([feed])
    success=FeedObservation(feed=feed,attempted_at=now+timedelta(seconds=1),completed_at=now+timedelta(seconds=2),article_count=2,warnings=['Malformed RSS'])
    repo.save_collection([article()], [success])
    status=repo.feed_status()[0]
    assert status['status']=='success' and status['warnings']==['Malformed RSS']
    failed=replace(success,attempted_at=now+timedelta(seconds=3),completed_at=now+timedelta(seconds=4),error='HTTP 404',article_count=0)
    repo.save_collection([], [failed])
    status=repo.feed_status()[0]
    assert status['status']=='error' and status['last_success_article_count']==2
    assert status['last_success']==success.completed_at.isoformat()
    repo.save_collection([], [success])
    assert repo.feed_status()[0]['status']=='error'
    with pytest.raises(psycopg.DataError):
        repo.save_collection([article(2)],[replace(failed,feed=replace_feed(feed,name='bad\x00name'))])
    assert repo.get(article_key(article(2))) is None


def replace_feed(feed,**kwargs):
    return feed.model_copy(update=kwargs)


def test_session_locks_share_database_and_release_across_repository_instances(repo):
    second=PostgreSQLArticleRepository(URL)
    with collector_lock(repo):
        with pytest.raises(CollectorBusy):
            with collector_lock(second):pass
        with worker_instance_lock(second):pass
    with collector_lock(second):pass
    with pytest.raises(ValueError):
        with collector_lock(repo):raise ValueError('abort')
    with collector_lock(second):pass
    with worker_instance_lock(repo):
        with pytest.raises(CollectorBusy):
            with worker_instance_lock(second):pass


def test_feed_configuration_persists_and_concurrent_updates_do_not_lose_rows(repo,tmp_path):
    directory=tmp_path/'feeds';directory.mkdir()
    (directory/'news.yaml').write_text('category: news\nfeeds:\n  - name: Default\n    url: https://example.com/default\n')
    registry=PostgreSQLFeedRegistry(repo,directory)
    assert registry.list()[0]['name']=='Default'
    repo.refresh([article()])
    def value(i):return dict(name=f'Source {i}',url=f'https://example.com/rss/{i}',category='news',enabled=True,description=None)
    with ThreadPoolExecutor(max_workers=2) as pool:
        saved=list(pool.map(lambda i:registry.save(value(i)),range(2)))
    assert len(registry.list())==3 and not repo.is_cache_valid()
    assert len(registry.configuration().categories[0].feeds)==3
    registry.save({**value(0),'enabled':False},feed_id=saved[0]['id'])
    assert len(registry.configuration().categories[0].feeds)==2
    with pytest.raises(FeedConflict):registry.save(value(1))
    with pytest.raises(FeedNotFound):registry.save(value(3),feed_id='missing')
    assert len(PostgreSQLFeedRegistry(PostgreSQLArticleRepository(URL),directory).list())==3


def test_sqlite_import_preserves_articles_configuration_telemetry_and_source(repo,tmp_path):
    source=tmp_path/'original.sqlite3'
    sqlite=SQLiteArticleRepository(source)
    feed=Feed(name='Source',url='https://example.com/rss',category='news')
    now=datetime.now(timezone.utc)
    sqlite.save_collection([article(),article(1)],[FeedObservation(feed=feed,attempted_at=now,completed_at=now,article_count=2)])
    directory=tmp_path/'feeds';directory.mkdir()
    registry=FeedRegistry(source,directory)
    registry.save(dict(name='Managed',url='https://example.com/managed',category='news',enabled=False,description=None))
    before=hashlib.sha256(source.read_bytes()).hexdigest()
    result=import_sqlite(repo,source)
    assert result=={'articles':2,'feeds':1,'already_imported':False}
    assert repo.load()==sqlite.load()
    assert repo.feed_status()==sqlite.feed_status()
    assert PostgreSQLFeedRegistry(repo,directory).list()==registry.list()
    assert hashlib.sha256(source.read_bytes()).hexdigest()==before
    assert import_sqlite(repo,source)['already_imported']
    sqlite.save([article(2)])
    with pytest.raises(ValueError,match='empty'):import_sqlite(repo,source)
    assert len(repo.load())==2


def test_import_refuses_existing_data_without_changes(repo,tmp_path):
    source=tmp_path/'original.sqlite3';sqlite=SQLiteArticleRepository(source);sqlite.save([article(2)])
    repo.save([article()])
    with pytest.raises(ValueError,match='empty'):import_sqlite(repo,source)
    assert repo.load()==[article()]


def test_search_ioc_actor_controls_work_with_postgres(repo):
    repo.save([article(),replace(article(1),threat_actors=['APT29'])])
    search=SearchService(repository=repo,engine=SearchEngine())
    rows=search.search(keyword='report',ioc='CVE-2021-44228',threat_actor='APT28',limit=10)
    assert rows==[article()]


def test_api_reads_configures_feeds_and_reports_external_backups(repo,tmp_path):
    repo.save([article()])
    directory=tmp_path/'feeds';directory.mkdir()
    with TestClient(create_app(repo,feed_directory=directory,database_file=tmp_path/'runtime.sqlite3')) as client:
        assert client.get('/health').json()=={'status':'ok'}
        assert client.get('/articles').json()['items'][0]['title']==article().title
        detail=client.get('/articles/detail',params={'id':article_key(article())}).json()
        assert detail['attack_details']['status']=='ok'
        assert detail['vulnerabilities'][0]['cve_id']=='CVE-2021-44228'
        assert client.get('/topics').status_code==200
        assert client.get('/search?q=report').json()['items']
        body=dict(name='Managed',url='https://example.com/managed',category='news',enabled=True)
        with collector_lock(repo):
            assert client.post('/feed-config',json=body,headers={'X-Cyber-RSS-Request':'1'}).status_code==409
        response=client.post('/feed-config',json=body,headers={'X-Cyber-RSS-Request':'1'})
        assert response.status_code==201
        assert client.get('/feed-config').json()['total']==1
        assert client.get('/backups').json()['supported'] is False
        assert client.get('/backups/status').json()['status']=='unsupported'
        assert client.post('/backups',headers={'X-Cyber-RSS-Request':'1'}).status_code==501
        assert client.get('/backups/missing/download').status_code==501
    assert not (tmp_path/'runtime.sqlite3').exists()


def test_manual_collection_and_worker_lock_with_postgres(repo,tmp_path):
    import feedparser
    from app.container import ApplicationContainer
    directory=tmp_path/'feeds';directory.mkdir()
    (directory/'news.yaml').write_text('category: news\nfeeds:\n  - name: Source\n    url: https://example.com/rss\n')
    def factory():
        container=ApplicationContainer(database_url=URL,database_file=tmp_path/'runtime.sqlite3',config_directory=directory,misp_auto_update=False)
        async def fetch():
            parsed=feedparser.parse('<rss version="2.0"><channel><title>Source</title><item><title>Fighting Ursa CVE-2021-44228 T1059.001</title><link>https://example.com/collected</link></item></channel></rss>')
            return [FeedResult(feed=Feed(name='Source',url='https://example.com/rss',category='news'),parsed=parsed)]
        container.fetcher.fetch_all=fetch
        return container.article_service
    with TestClient(create_app(repo,feed_directory=directory,database_file=tmp_path/'runtime.sqlite3',collection_service_factory=factory)) as client:
        with collector_lock(repo):
            assert client.post('/collection',json={},headers={'X-Cyber-RSS-Request':'1'}).status_code==409
        assert client.post('/collection',json={},headers={'X-Cyber-RSS-Request':'1'}).status_code==202
        for _ in range(100):
            state=client.get('/collection').json()
            if state['status']!='running':break
            time.sleep(.05)
        assert state['status']=='completed',state
        saved=repo.load()[0]
        assert saved.threat_actors==['APT28'] and saved.cve_ids==['CVE-2021-44228']
        assert saved.attack.technique_ids==['T1059.001']
        assert repo.feed_status()[0]['status']=='success'
    assert not (tmp_path/'runtime.sqlite3').exists()


def test_cli_and_worker_are_excluded_by_postgres_collector_lock(repo,tmp_path):
    import subprocess
    import sys
    directory=tmp_path/'feeds';directory.mkdir()
    environment={**os.environ,'CYBER_RSS_DATABASE_URL':URL,'CYBER_RSS_DATA_DIR':str(tmp_path),'CYBER_RSS_FEED_DIR':str(directory),'CYBER_RSS_MISP_AUTO_UPDATE':'0'}
    environment.pop('CYBER_RSS_DATABASE_URL_FILE',None)
    with collector_lock(repo):
        cli=subprocess.run([sys.executable,'-m','app.main','update','--refresh'],env=environment,capture_output=True,text=True,timeout=20)
        assert cli.returncode==1 and 'already running' in cli.stderr
        worker=subprocess.run([sys.executable,'-m','app.worker','--once','--feeds',str(directory)],env=environment,capture_output=True,text=True,timeout=20)
        assert worker.returncode==1 and 'already running' in worker.stderr
    with collector_lock(repo):pass


def test_sqlite_import_rollback_and_dry_run_do_not_modify_archives(repo,tmp_path,monkeypatch,capsys):
    from tools import import_postgres
    source=tmp_path/'original.sqlite3';sqlite=SQLiteArticleRepository(source);sqlite.save([article()])
    monkeypatch.setattr('sys.argv',['rss-import-postgres','--sqlite',str(source),'--dry-run'])
    import_postgres.main()
    assert json.loads(capsys.readouterr().out)['articles']==1
    assert repo.load()==[]
    with sqlite._connection() as connection:
        connection.execute("UPDATE articles SET first_seen='not-a-date'")
    with pytest.raises(ValueError):import_sqlite(repo,source)
    assert repo.load()==[]
    with repo._connection() as connection:
        assert connection.execute("SELECT value FROM cyber_rss.metadata WHERE key='sqlite_imported_digest'").fetchone() is None


def test_api_factory_selects_postgres_from_secret_file_and_collects_without_sqlite(repo,tmp_path,monkeypatch):
    secret=tmp_path/'url';secret.write_text(URL)
    monkeypatch.delenv('CYBER_RSS_DATABASE_URL',raising=False)
    monkeypatch.setenv('CYBER_RSS_DATABASE_URL_FILE',str(secret))
    monkeypatch.setenv('CYBER_RSS_MISP_AUTO_UPDATE','0')
    directory=tmp_path/'feeds';directory.mkdir()
    with TestClient(create_app(database_file=tmp_path/'archive.sqlite3',feed_directory=directory)) as client:
        assert client.get('/health').json()=={'status':'ok'}
        assert client.get('/backups/status').json()['status']=='unsupported'
        assert client.post('/collection',json={},headers={'X-Cyber-RSS-Request':'1'}).status_code==202
        for _ in range(100):
            state=client.get('/collection').json()
            if state['status']!='running':break
            time.sleep(.05)
        assert state['status']=='completed',state
    assert not (tmp_path/'archive.sqlite3').exists()


def test_unknown_schema_version_fails_without_rewriting_existing_archive(repo):
    repo.save([article()])
    with repo._connection() as connection:
        repo._set_metadata(connection,'schema_version','99')
    try:
        with pytest.raises(ValueError,match='schema version'):PostgreSQLArticleRepository(URL)
        with repo._connection() as connection:
            assert connection.execute("SELECT value FROM cyber_rss.metadata WHERE key='schema_version'").fetchone()[0]=='99'
        assert repo.load()==[article()]
    finally:
        with repo._connection() as connection:repo._set_metadata(connection,'schema_version','1')


def test_same_timestamp_and_case_sensitive_facets_have_sqlite_order(repo,tmp_path):
    sqlite=SQLiteArticleRepository(tmp_path/'archive.sqlite3')
    rows=[replace(article(),url='https://example.com/'+suffix,source=suffix,category=suffix,tags=[suffix])
          for suffix in ('a','A','z','Z','é','É')]
    repo.save(rows);sqlite.save(rows)
    assert repo.load()==sqlite.load()
    assert repo.latest(limit=3,offset=2)==sqlite.latest(limit=3,offset=2)
    assert repo.filters()==sqlite.filters()
