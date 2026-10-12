"""Read-only SQLite import into an empty PostgreSQL archive, committed atomically."""
from contextlib import closing
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3

from parser.dates import normalize_datetime
from storage.postgres_storage import LOCK_KEYS, key_hash
from storage.utils import article_from_dict, article_key, article_to_dict


def sqlite_snapshot(source: Path):
    source=source.resolve()
    if not source.is_file():
        raise FileNotFoundError(source)
    with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True,timeout=30)) as connection:
        connection.row_factory=sqlite3.Row
        connection.execute('BEGIN')
        version=connection.execute('PRAGMA user_version').fetchone()[0]
        if version not in (1,2) or connection.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
            raise ValueError('Unsupported or damaged SQLite archive')
        articles=[dict(row) for row in connection.execute('SELECT * FROM articles ORDER BY id')]
        feeds=[dict(row) for row in connection.execute('SELECT * FROM feed_status ORDER BY url')] if version==2 else []
        metadata=dict(connection.execute('SELECT key,value FROM metadata'))
    # Validate before opening a transaction in the destination.
    for row in articles:
        article=article_from_dict(json.loads(row['payload']))
        if article_key(article)!=row['id']:
            raise ValueError('SQLite article identity does not match its payload')
    for row in feeds:
        if not isinstance(json.loads(row.get('warnings','[]')),list):
            raise ValueError('Invalid SQLite collection warnings')
    if 'managed_feeds' in metadata and not isinstance(json.loads(metadata['managed_feeds']),list):
        raise ValueError('Invalid SQLite feed configuration')
    contents={'articles':articles,'feeds':feeds,'metadata':metadata}
    digest=hashlib.sha256(json.dumps(contents,sort_keys=True).encode()).hexdigest()
    return contents,digest


def import_sqlite(repository, source: Path):
    snapshot,digest=sqlite_snapshot(source)
    def date(value):
        return normalize_datetime(datetime.fromisoformat(value)) if value else None
    with repository.advisory_lock('collector'):
        with repository._connection() as connection:
            connection.execute('SELECT pg_advisory_xact_lock(%s)',(LOCK_KEYS['import'],))
            marker=connection.execute("SELECT value FROM cyber_rss.metadata WHERE key='sqlite_imported_digest'").fetchone()
            if marker and marker[0]==digest:
                return {'articles':0,'feeds':0,'already_imported':True}
            occupied=connection.execute('''SELECT EXISTS(SELECT 1 FROM cyber_rss.articles)
                OR EXISTS(SELECT 1 FROM cyber_rss.feed_status)
                OR EXISTS(SELECT 1 FROM cyber_rss.metadata WHERE key!='schema_version')''').fetchone()[0]
            if occupied:
                raise ValueError('PostgreSQL destination must be empty; existing history is never overwritten')
            for row in snapshot['articles']:
                article=article_from_dict(json.loads(row['payload']))
                connection.execute('INSERT INTO cyber_rss.articles VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                                   (key_hash(row['id']),row['id'],repository._jsonb(article_to_dict(article)),
                                    date(row['published']),article.source.casefold(),article.category.casefold() if article.category else None,
                                    [tag.casefold() for tag in article.tags],date(row['first_seen']),date(row['last_seen'])))
            for row in snapshot['feeds']:
                connection.execute('INSERT INTO cyber_rss.feed_status VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                                   (key_hash(row['url']),row['url'],row['name'],row['category'],row['status'],
                                    date(row['last_attempt']),date(row['last_success']),row['last_error'],row['article_count'],
                                    row.get('last_success_article_count'),repository._jsonb(json.loads(row.get('warnings','[]')))))
            for key,value in snapshot['metadata'].items():
                if key not in ('schema_version','sqlite_imported_digest','sqlite_imported_source'):
                    repository._set_metadata(connection,key,value)
            repository._set_metadata(connection,'sqlite_imported_digest',digest)
            repository._set_metadata(connection,'sqlite_imported_source',str(source.resolve()))
    return {'articles':len(snapshot['articles']),'feeds':len(snapshot['feeds']),'already_imported':False}
