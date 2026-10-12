import pytest
from storage.factory import create_repository,database_url_from_environment
from storage.sqlite_storage import SQLiteArticleRepository
from storage.json_storage import JsonArticleRepository


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    monkeypatch.delenv('CYBER_RSS_DATABASE_URL',raising=False)
    monkeypatch.delenv('CYBER_RSS_DATABASE_URL_FILE',raising=False)


def test_sqlite_default_and_explicit_legacy_json(tmp_path):
    assert isinstance(create_repository(database_file=tmp_path/'archive.sqlite3'),SQLiteArticleRepository)
    assert isinstance(create_repository(cache_file=tmp_path/'archive.json'),JsonArticleRepository)


def test_environment_url_secret_file_and_explicit_precedence(tmp_path,monkeypatch):
    from storage import postgres_storage
    class FakeRepository:
        def __init__(self,url,duration,**kwargs):self.url=url
    monkeypatch.setattr(postgres_storage,'PostgreSQLArticleRepository',FakeRepository)
    monkeypatch.setenv('CYBER_RSS_DATABASE_URL','postgresql://server/rss')
    assert create_repository().url=='postgresql://server/rss'
    assert isinstance(create_repository(database_file=tmp_path/'archive.sqlite3',database_url=''),SQLiteArticleRepository)
    secret=tmp_path/'url';secret.write_text('postgresql://other/rss\n')
    monkeypatch.delenv('CYBER_RSS_DATABASE_URL')
    monkeypatch.setenv('CYBER_RSS_DATABASE_URL_FILE',str(secret))
    assert create_repository().url=='postgresql://other/rss'
    monkeypatch.setenv('CYBER_RSS_DATABASE_URL','postgresql://server/rss')
    with pytest.raises(ValueError,match='only one'):database_url_from_environment()


def test_invalid_url_does_not_echo_credentials_and_empty_secret_does_not_fall_back(tmp_path,monkeypatch):
    with pytest.raises(ValueError) as exc:create_repository(database_url='mysql://user:private-password@server/rss')
    assert 'private-password' not in str(exc.value)
    secret=tmp_path/'empty';secret.write_text('')
    monkeypatch.setenv('CYBER_RSS_DATABASE_URL_FILE',str(secret))
    with pytest.raises(ValueError,match='empty'):create_repository(database_file=tmp_path/'archive.sqlite3')
    assert not (tmp_path/'archive.sqlite3').exists()
    with pytest.raises(ValueError):create_repository(cache_file=tmp_path/'cache.json',database_url='postgresql://server/rss')


def test_postgres_extra_is_optional_and_reports_missing_dependency(monkeypatch):
    import builtins
    from storage.postgres_storage import driver
    original=builtins.__import__
    def blocked(name,*args,**kwargs):
        if name=='psycopg':raise ImportError('missing')
        return original(name,*args,**kwargs)
    monkeypatch.setattr(builtins,'__import__',blocked)
    with pytest.raises(RuntimeError,match='postgres'):driver()


def test_postgres_mode_cannot_silently_create_sqlite_backup(tmp_path,monkeypatch):
    from tools import backup_database,backup_worker
    monkeypatch.setenv('CYBER_RSS_DATABASE_URL','postgresql://server/rss')
    for module in (backup_database,backup_worker):
        monkeypatch.setattr('sys.argv',['rss-backup'])
        with pytest.raises(SystemExit) as exc:module.main()
        assert exc.value.code==2
