"""Transactional PostgreSQL archive with the same contract as SQLite."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib

from parser.dates import normalize_datetime
from storage.interfaces import ArticleRepository
from storage.utils import article_from_dict, article_key, article_to_dict
from storage.migrations import migrate_postgres
from alerts.outbox import enqueue
from storage.retention import RetentionPolicy, prune

LOCK_KEYS = {'schema': 73941101, 'collector': 73941102, 'worker-instance': 73941103, 'feed-registry': 73941104, 'import': 73941105, 'retention': 73941106}


def driver():
    try:
        import psycopg
        from psycopg.types.json import Jsonb
    except ImportError as exc:
        raise RuntimeError('PostgreSQL requires: pip install ".[postgres]"') from exc
    return psycopg, Jsonb


def key_hash(identifier):
    return hashlib.sha256(identifier.encode()).digest()


class PostgreSQLArticleRepository(ArticleRepository):
    backend = 'postgresql'

    def __init__(self, database_url, cache_duration=timedelta(hours=6), *, retention=None):
        self._database_url = database_url
        self.cache_duration = cache_duration
        self.retention = retention or RetentionPolicy()
        self._psycopg, self._jsonb = driver()
        with self._connection() as connection:
            migrate_postgres(connection, LOCK_KEYS['schema'])

    def prune(self, policy=None, *, dry_run=True, now=None):
        with self._connection() as connection:
            if dry_run:
                connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            else:
                connection.execute('SELECT pg_advisory_xact_lock(%s)', (LOCK_KEYS['retention'],))
            return prune(connection, policy or self.retention, backend='postgresql', dry_run=dry_run, now=now)

    @contextmanager
    def _connection(self, *, autocommit=False):
        with self._psycopg.connect(self._database_url, connect_timeout=10, autocommit=autocommit,
                                  application_name='cyber-rss-reader') as connection:
            connection.execute("SET statement_timeout='30s'")
            connection.execute("SET lock_timeout='10s'")
            yield connection

    @contextmanager
    def advisory_lock(self, name):
        from storage.locks import CollectorBusy
        with self._connection(autocommit=True) as connection:
            if not connection.execute('SELECT pg_try_advisory_lock(%s)', (LOCK_KEYS[name],)).fetchone()[0]:
                raise CollectorBusy('Another collector is already running for this database')
            try:
                yield
            finally:
                connection.execute('SELECT pg_advisory_unlock(%s)', (LOCK_KEYS[name],))

    def _set_metadata(self, connection, key, value):
        connection.execute('INSERT INTO cyber_rss.metadata VALUES (%s,%s) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, value))

    def _upsert(self, connection, articles):
        now = datetime.now(timezone.utc)
        values = []
        for article in articles:
            identifier = article_key(article)
            values.append((key_hash(identifier),identifier,self._jsonb(article_to_dict(article)),
                           normalize_datetime(article.published) if article.published else None,
                           article.source.casefold(),article.category.casefold() if article.category else None,
                           [tag.casefold() for tag in article.tags],now,now))
        if values:
            with connection.cursor() as cursor:
                cursor.executemany('''INSERT INTO cyber_rss.articles VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT(key_hash) DO UPDATE SET payload=excluded.payload,published=excluded.published,
                    source=excluded.source,category=excluded.category,tags=excluded.tags,last_seen=excluded.last_seen
                    WHERE articles.id=excluded.id''',values)
                if cursor.rowcount != len(values):
                    raise ValueError('Article identity hash collision')

    def save(self, articles):
        with self._connection() as connection:
            self._upsert(connection, articles)

    def update_tags(self, articles):
        values = [(self._jsonb(article_to_dict(article)), [tag.casefold() for tag in article.tags],
                   key_hash(article_key(article)), article_key(article)) for article in articles]
        if values:
            with self._connection() as connection, connection.cursor() as cursor:
                cursor.executemany('UPDATE cyber_rss.articles SET payload=%s,tags=%s '
                                   'WHERE key_hash=%s AND id=%s', values)

    def refresh(self, articles):
        if not articles:
            return
        with self._connection() as connection:
            if self.retention.enabled:
                connection.execute('SELECT pg_advisory_xact_lock(%s)', (LOCK_KEYS['retention'],))
            self._upsert(connection, articles)
            self._set_metadata(connection,'last_refresh',datetime.now(timezone.utc).isoformat())
            if self.retention.enabled:
                prune(connection, self.retention, backend='postgresql')

    def load(self):
        with self._connection() as connection:
            rows = connection.execute('SELECT payload FROM cyber_rss.articles ORDER BY published DESC NULLS LAST,id COLLATE "C"').fetchall()
        return [article_from_dict(row[0]) for row in rows]

    def get(self, article_id):
        with self._connection() as connection:
            row = connection.execute('SELECT payload FROM cyber_rss.articles WHERE key_hash=%s AND id=%s',
                                     (key_hash(article_id),article_id)).fetchone()
        return article_from_dict(row[0]) if row else None

    def latest(self, *, category=None, source=None, tag=None, limit=20, offset=0):
        if limit < 1 or offset < 0:
            raise ValueError('limit must be positive and offset nonnegative')
        clauses, parameters = [], []
        for field, value in (('category',category),('source',source)):
            if value:
                clauses.append(field+'=%s')
                parameters.append(value.casefold())
        if tag:
            clauses.append('tags @> %s::text[]')
            parameters.append([tag.casefold()])
        where = ' WHERE '+' AND '.join(clauses) if clauses else ''
        with self._connection() as connection:
            rows = connection.execute('SELECT payload FROM cyber_rss.articles'+where+
                                      ' ORDER BY published DESC NULLS LAST,id COLLATE "C" LIMIT %s OFFSET %s',
                                      [*parameters,limit,offset]).fetchall()
        return [article_from_dict(row[0]) for row in rows]

    def filters(self):
        with self._connection() as connection:
            total = connection.execute('SELECT COUNT(*) FROM cyber_rss.articles').fetchone()[0]
            groups = {}
            for field in ('category','source'):
                groups[field] = connection.execute(f"SELECT (payload->>'{field}') COLLATE \"C\" AS label,COUNT(*) FROM cyber_rss.articles "
                                                   f"WHERE COALESCE(payload->>'{field}','')!='' GROUP BY label ORDER BY label").fetchall()
            tags = connection.execute('SELECT tag COLLATE "C" AS label,COUNT(DISTINCT key_hash) FROM cyber_rss.articles, '
                                      "LATERAL jsonb_array_elements_text(payload->'tags') AS tag GROUP BY label ORDER BY label").fetchall()
        return {'total':total,'categories':[{'value':v,'count':n} for v,n in groups['category']],
                'sources':[{'value':v,'count':n} for v,n in groups['source']],
                'tags':[{'value':v,'count':n} for v,n in tags]}

    def begin_feed_collection(self, feeds):
        now = datetime.now(timezone.utc)
        with self._connection() as connection:
            for feed in feeds:
                url = str(feed.url)
                connection.execute('''INSERT INTO cyber_rss.feed_status(url_hash,url,name,category,status,last_attempt)
                    VALUES (%s,%s,%s,%s,'collecting',%s) ON CONFLICT(url_hash) DO UPDATE SET name=excluded.name,
                    category=excluded.category,status='collecting',last_attempt=excluded.last_attempt''',
                                   (key_hash(url),url,feed.name,feed.category,now))

    def save_collection(self, articles, observations):
        apply_retention = self.retention.enabled and any(item.error is None for item in observations)
        with self._connection() as connection:
            if apply_retention:
                connection.execute('SELECT pg_advisory_xact_lock(%s)', (LOCK_KEYS['retention'],))
            enqueue(connection, articles, getattr(self, 'alert_settings', None), 'postgresql')
            self._upsert(connection, articles)
            if articles:
                self._set_metadata(connection,'last_refresh',datetime.now(timezone.utc).isoformat())
            for observation in observations:
                success = observation.error is None
                url = str(observation.feed.url)
                connection.execute('''INSERT INTO cyber_rss.feed_status VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT(url_hash) DO UPDATE SET name=excluded.name,category=excluded.category,status=excluded.status,
                    last_attempt=excluded.last_attempt,last_error=excluded.last_error,article_count=excluded.article_count,
                    warnings=excluded.warnings,last_success=COALESCE(excluded.last_success,feed_status.last_success),
                    last_success_article_count=COALESCE(excluded.last_success_article_count,feed_status.last_success_article_count)
                    WHERE excluded.last_attempt>=feed_status.last_attempt''',
                                   (key_hash(url),url,observation.feed.name,observation.feed.category,'success' if success else 'error',
                                    normalize_datetime(observation.attempted_at),normalize_datetime(observation.completed_at) if success else None,
                                    observation.error,observation.article_count,observation.article_count if success else None,
                                    self._jsonb(observation.warnings)))
            if apply_retention:
                return prune(connection, self.retention, backend='postgresql')

    def feed_status(self):
        from psycopg.rows import dict_row
        with self._connection() as connection:
            rows = connection.cursor(row_factory=dict_row).execute('SELECT * FROM cyber_rss.feed_status ORDER BY lower(name),url').fetchall()
        for row in rows:
            row.pop('url_hash')
            for field in ('last_attempt','last_success'):
                if row[field] is not None:
                    row[field] = normalize_datetime(row[field]).isoformat()
        return rows

    def clear(self):
        with self._connection() as connection:
            connection.execute('DELETE FROM cyber_rss.articles')
            connection.execute("DELETE FROM cyber_rss.metadata WHERE key='last_refresh'")

    def is_cache_valid(self):
        with self._connection() as connection:
            row = connection.execute("SELECT value FROM cyber_rss.metadata WHERE key='last_refresh'").fetchone()
        return bool(row and datetime.now(timezone.utc)<normalize_datetime(datetime.fromisoformat(row[0]))+self.cache_duration)
