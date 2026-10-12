from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3

from parser.models import Article
from parser.dates import normalize_datetime
from storage.interfaces import ArticleRepository
from storage.json_storage import JsonArticleRepository
from storage.utils import article_from_dict, article_key, article_to_dict
from feeds.models import FeedObservation
from config.models import Feed
from storage.migrations import migrate_sqlite
from storage.retention import RetentionPolicy, RetentionResult, prune


class SQLiteArticleRepository(ArticleRepository):
    """Transactional archive with optional retention after collection."""

    def __init__(self, database_file: Path,
                 cache_duration: timedelta = timedelta(hours=6), *, retention: RetentionPolicy | None = None) -> None:
        self.database_file = database_file
        self.cache_duration = cache_duration
        self.retention = retention or RetentionPolicy()
        database_file.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            migrate_sqlite(connection)
            connection.execute("PRAGMA journal_mode=WAL")

    def prune(self, policy=None, *, dry_run=True, now=None):
        with self._connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            return prune(connection, policy or self.retention, backend='sqlite', dry_run=dry_run, now=now)

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.database_file, timeout=30)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _upsert(self, connection, articles: list[Article]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        for article in articles:
            connection.execute("""
                INSERT INTO articles VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    payload=excluded.payload, published=excluded.published,
                    source=excluded.source, category=excluded.category,
                    tags=excluded.tags, last_seen=excluded.last_seen
            """, (article_key(article), json.dumps(article_to_dict(article)),
                  normalize_datetime(article.published).isoformat() if article.published else None,
                  article.source.casefold(), article.category.casefold() if article.category else None,
                  json.dumps([tag.casefold() for tag in article.tags]), now, now))

    def save(self, articles: list[Article]) -> None:
        with self._connection() as connection:
            self._upsert(connection, articles)

    def refresh(self, articles: list[Article]) -> None:
        if not articles:
            return
        with self._connection() as connection:
            self._upsert(connection, articles)
            connection.execute("INSERT OR REPLACE INTO metadata VALUES ('last_refresh', ?)",
                               (datetime.now(timezone.utc).isoformat(),))
            if self.retention.enabled:
                prune(connection, self.retention, backend='sqlite')

    def load(self) -> list[Article]:
        with self._connection() as connection:
            rows = connection.execute("SELECT payload FROM articles ORDER BY published DESC, id").fetchall()
        return [article_from_dict(json.loads(row[0])) for row in rows]

    def get(self, article_id: str) -> Article | None:
        with self._connection() as connection:
            row = connection.execute('SELECT payload FROM articles WHERE id=?', (article_id,)).fetchone()
        return article_from_dict(json.loads(row[0])) if row else None

    def filters(self) -> dict:
        with self._connection() as connection:
            total = connection.execute('SELECT COUNT(*) FROM articles').fetchone()[0]
            groups = {}
            # Preserve the display spelling in the payload; indexed columns are casefolded.
            for field in ('category', 'source'):
                rows = connection.execute(f"""
                    SELECT json_extract(payload, '$.{field}') AS label, COUNT(*)
                    FROM articles WHERE json_extract(payload, '$.{field}') IS NOT NULL
                    AND json_extract(payload, '$.{field}') != '' GROUP BY label ORDER BY label
                """).fetchall()
                groups[field] = rows
            tags = connection.execute("""
                SELECT value, COUNT(DISTINCT articles.id) FROM articles,
                json_each(json_extract(payload, '$.tags')) GROUP BY value ORDER BY value
            """).fetchall()
        return {'total': total,
                'categories': [{'value': value, 'count': count} for value, count in groups['category']],
                'sources': [{'value': value, 'count': count} for value, count in groups['source']],
                'tags': [{'value': value, 'count': count} for value, count in tags]}

    def begin_feed_collection(self, feeds: list[Feed]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as connection:
            for feed in feeds:
                connection.execute("""
                    INSERT INTO feed_status(url, name, category, status, last_attempt)
                    VALUES (?, ?, ?, 'collecting', ?)
                    ON CONFLICT(url) DO UPDATE SET name=excluded.name, category=excluded.category,
                        status='collecting', last_attempt=excluded.last_attempt
                """, (str(feed.url), feed.name, feed.category, now))

    def save_collection(self, articles: list[Article], observations: list[FeedObservation]) -> RetentionResult | None:
        """Commit articles and their collection outcomes together."""
        with self._connection() as connection:
            self._upsert(connection, articles)
            if articles:
                connection.execute("INSERT OR REPLACE INTO metadata VALUES ('last_refresh', ?)",
                                   (datetime.now(timezone.utc).isoformat(),))
            for observation in observations:
                success = observation.error is None
                connection.execute("""
                    INSERT INTO feed_status (
                        url, name, category, status, last_attempt, last_success, last_error,
                        article_count, last_success_article_count, warnings
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(url) DO UPDATE SET
                        name=excluded.name, category=excluded.category, status=excluded.status,
                        last_attempt=excluded.last_attempt, last_error=excluded.last_error,
                        article_count=excluded.article_count, warnings=excluded.warnings,
                        last_success=COALESCE(excluded.last_success, feed_status.last_success),
                        last_success_article_count=COALESCE(excluded.last_success_article_count,
                                                           feed_status.last_success_article_count)
                    WHERE excluded.last_attempt >= feed_status.last_attempt
                """, (str(observation.feed.url), observation.feed.name, observation.feed.category,
                      'success' if success else 'error',
                      normalize_datetime(observation.attempted_at).isoformat(),
                      normalize_datetime(observation.completed_at).isoformat() if success else None,
                      observation.error, observation.article_count,
                      observation.article_count if success else None,
                      json.dumps(observation.warnings)))
            if self.retention.enabled and any(item.error is None for item in observations):
                return prune(connection, self.retention, backend='sqlite')

    def feed_status(self) -> list[dict]:
        with self._connection() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute('SELECT * FROM feed_status ORDER BY name COLLATE NOCASE, url').fetchall()
        return [{**dict(row), 'warnings': json.loads(row['warnings'])} for row in rows]

    def latest(self, *, category=None, source=None, tag=None,
               limit: int = 20, offset: int = 0) -> list[Article]:
        if limit < 1 or offset < 0:
            raise ValueError("limit must be positive and offset nonnegative")
        clauses, parameters = [], []
        for field, value in (("category", category), ("source", source)):
            if value:
                clauses.append(f"{field} = ?")
                parameters.append(value.casefold())
        if tag:
            clauses.append("EXISTS (SELECT 1 FROM json_each(articles.tags) WHERE value = ?)")
            parameters.append(tag.casefold())
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT payload FROM articles" + where +
                " ORDER BY published DESC, id LIMIT ? OFFSET ?",
                [*parameters, limit, offset],
            ).fetchall()
        return [article_from_dict(json.loads(row[0])) for row in rows]

    def clear(self) -> None:
        with self._connection() as connection:
            connection.execute("DELETE FROM articles")
            connection.execute("DELETE FROM metadata WHERE key = 'last_refresh'")

    def is_cache_valid(self) -> bool:
        with self._connection() as connection:
            row = connection.execute("SELECT value FROM metadata WHERE key='last_refresh'").fetchone()
        return bool(row and datetime.now(timezone.utc) <
                    normalize_datetime(datetime.fromisoformat(row[0])) + self.cache_duration)

    def import_json(self, cache_file: Path) -> int:
        """Import once, atomically; never modify or delete the source file."""
        articles = JsonArticleRepository(cache_file, self.cache_duration).load()
        if not cache_file.exists():
            raise FileNotFoundError(cache_file)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM metadata WHERE key='legacy_json_imported'").fetchone():
                return 0
            self._upsert(connection, articles)
            connection.execute("INSERT INTO metadata VALUES ('legacy_json_imported', ?)",
                               (str(cache_file.resolve()),))
        return len({article_key(article) for article in articles})
