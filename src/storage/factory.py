"""Select storage explicitly; SQLite is the default without a database URL."""
from datetime import timedelta
import os
from pathlib import Path
from urllib.parse import urlsplit

from config.paths import ARTICLE_DATABASE_FILE
from storage.json_storage import JsonArticleRepository
from storage.sqlite_storage import SQLiteArticleRepository


def database_url_from_environment():
    value = os.environ.get('CYBER_RSS_DATABASE_URL','').strip()
    file = os.environ.get('CYBER_RSS_DATABASE_URL_FILE')
    if value and file:
        raise ValueError('Configure only one of CYBER_RSS_DATABASE_URL and CYBER_RSS_DATABASE_URL_FILE')
    if file:
        value = Path(file).read_text().strip()
        if not value:
            raise ValueError('Database URL file is empty')
    return value


def create_repository(*, database_file=ARTICLE_DATABASE_FILE, cache_file=None, database_url=None,
                      cache_duration=timedelta(hours=6)):
    if cache_file is not None:
        if database_url:
            raise ValueError('A JSON cache and a PostgreSQL URL cannot be selected together')
        return JsonArticleRepository(cache_file,cache_duration)
    value = database_url_from_environment() if database_url is None else database_url
    if not value:
        return SQLiteArticleRepository(database_file,cache_duration)
    try:
        scheme = urlsplit(value).scheme
    except ValueError:
        scheme = None
    if scheme not in ('postgres','postgresql'):
        raise ValueError('Unsupported database URL; use postgres:// or postgresql://')
    from storage.postgres_storage import PostgreSQLArticleRepository
    return PostgreSQLArticleRepository(value,cache_duration)


def is_postgres(repository):
    return getattr(repository,'backend',None)=='postgresql'
