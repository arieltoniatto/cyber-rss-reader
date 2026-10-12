"""Read-only schema/retention inspection independent of repository initialization."""
from contextlib import closing
from pathlib import Path
import sqlite3

from storage.migrations import SQLITE_MIGRATIONS,POSTGRES_MIGRATIONS,postgres_current,status
from storage.postgres_storage import driver
from storage.retention import prune,RetentionResult


def _sqlite_status(connection):
    current=connection.execute('PRAGMA user_version').fetchone()[0]
    exists=connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'").fetchone()
    rows=connection.execute('SELECT version,name,checksum,applied_at,adopted FROM schema_migrations ORDER BY version').fetchall() if exists else []
    if exists and current and not rows:
        raise ValueError('Migration journal is incomplete')
    return status(current,SQLITE_MIGRATIONS,rows,'sqlite')


def sqlite_status(path):
    path=Path(path)
    if not path.exists():
        return status(0,SQLITE_MIGRATIONS,[],'sqlite')
    with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=30)) as connection:
        connection.execute('BEGIN')
        return _sqlite_status(connection)


def _postgres_status(connection):
    current=postgres_current(connection)
    exists=connection.execute("SELECT to_regclass('cyber_rss.schema_migrations')").fetchone()[0]
    rows=connection.execute('SELECT version,name,checksum,applied_at,adopted FROM cyber_rss.schema_migrations ORDER BY version').fetchall() if exists else []
    if exists and current and not rows:
        raise ValueError('Migration journal is incomplete')
    return status(current,POSTGRES_MIGRATIONS,rows,'postgresql')


def postgres_status(url):
    psycopg,_=driver()
    with psycopg.connect(url,connect_timeout=10) as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        return _postgres_status(connection)


def preview_retention(policy, *, database_file=None, database_url=None):
    if database_url:
        psycopg,_=driver()
        with psycopg.connect(database_url,connect_timeout=10) as connection:
            connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            report=_postgres_status(connection)
            if report['current_version']==0:
                return RetentionResult(policy,True,None,0,0,0,0)
            return prune(connection,policy,backend='postgresql',dry_run=True)
    path=Path(database_file)
    if not path.exists():
        return RetentionResult(policy,True,None,0,0,0,0)
    with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=30)) as connection:
        connection.execute('BEGIN')
        report=_sqlite_status(connection)
        if report['current_version']==0:
            return RetentionResult(policy,True,None,0,0,0,0)
        return prune(connection,policy,backend='sqlite',dry_run=True)
