"""Append-only, transactional schema migrations and legacy-version adoption."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    statements: tuple[str, ...]

    @property
    def checksum(self):
        return hashlib.sha256(json.dumps([self.version, self.name, self.statements]).encode()).hexdigest()


SQLITE_MIGRATIONS = (
    Migration(1, 'article_archive', (
        'CREATE TABLE IF NOT EXISTS articles (\n                    id TEXT PRIMARY KEY, payload TEXT NOT NULL,\n                    published TEXT, source TEXT NOT NULL, category TEXT,\n                    tags TEXT NOT NULL, first_seen TEXT NOT NULL,\n                    last_seen TEXT NOT NULL\n                )',
        'CREATE INDEX IF NOT EXISTS articles_published ON articles(published DESC, id)',
        'CREATE INDEX IF NOT EXISTS articles_source ON articles(source, published DESC)',
        'CREATE INDEX IF NOT EXISTS articles_category ON articles(category, published DESC)',
        'CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
    )),
    Migration(2, 'feed_collection_telemetry', (
        "CREATE TABLE IF NOT EXISTS feed_status (\n                    url TEXT PRIMARY KEY, name TEXT NOT NULL, category TEXT,\n                    status TEXT NOT NULL CHECK(status IN ('collecting', 'success', 'error')),\n                    last_attempt TEXT NOT NULL, last_success TEXT, last_error TEXT,\n                    article_count INTEGER NOT NULL DEFAULT 0,\n                    last_success_article_count INTEGER,\n                    warnings TEXT NOT NULL DEFAULT '[]'\n                )",
    )),
    Migration(3, 'retention_last_seen_index', (
        'CREATE INDEX IF NOT EXISTS articles_last_seen ON articles(julianday(last_seen), published DESC, id)',
    )),
)
POSTGRES_MIGRATIONS = (
    Migration(1, 'article_archive_and_telemetry', (
        'CREATE SCHEMA IF NOT EXISTS cyber_rss',
        'CREATE TABLE IF NOT EXISTS cyber_rss.metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL)',
        'CREATE TABLE IF NOT EXISTS cyber_rss.articles (\n                key_hash BYTEA PRIMARY KEY,id TEXT NOT NULL,payload JSONB NOT NULL,\n                published TIMESTAMPTZ,source TEXT NOT NULL,category TEXT,tags TEXT[] NOT NULL,\n                first_seen TIMESTAMPTZ NOT NULL,last_seen TIMESTAMPTZ NOT NULL)',
        'CREATE INDEX IF NOT EXISTS articles_published ON cyber_rss.articles(published DESC,key_hash)',
        'CREATE INDEX IF NOT EXISTS articles_source ON cyber_rss.articles(source,published DESC)',
        'CREATE INDEX IF NOT EXISTS articles_category ON cyber_rss.articles(category,published DESC)',
        'CREATE INDEX IF NOT EXISTS articles_tags ON cyber_rss.articles USING GIN(tags)',
        "CREATE TABLE IF NOT EXISTS cyber_rss.feed_status (\n                url_hash BYTEA PRIMARY KEY,url TEXT NOT NULL,name TEXT NOT NULL,category TEXT,\n                status TEXT NOT NULL CHECK(status IN ('collecting','success','error')),\n                last_attempt TIMESTAMPTZ NOT NULL,last_success TIMESTAMPTZ,last_error TEXT,\n                article_count INTEGER NOT NULL DEFAULT 0,last_success_article_count INTEGER,\n                warnings JSONB NOT NULL DEFAULT '[]'::jsonb)",
    )),
    Migration(2, 'retention_last_seen_index', (
        'CREATE INDEX IF NOT EXISTS articles_last_seen ON cyber_rss.articles(last_seen DESC, published DESC, key_hash)',
    )),
)
SQLITE_SCHEMA_VERSION = SQLITE_MIGRATIONS[-1].version
POSTGRES_SCHEMA_VERSION = POSTGRES_MIGRATIONS[-1].version
SUPPORTED_SQLITE_VERSIONS = tuple(range(1, SQLITE_SCHEMA_VERSION + 1))


def validate_chain(migrations):
    if not migrations or [item.version for item in migrations] != list(range(1, len(migrations) + 1)):
        raise ValueError('Migration versions must be consecutive, starting at 1')


def validate_history(current, migrations, rows):
    validate_chain(migrations)
    if type(current) is not int or not 0 <= current <= migrations[-1].version:
        raise ValueError('Unsupported database schema version')
    if rows and [row[0] for row in rows] != list(range(1,current+1)):
        raise ValueError('Migration journal is incomplete')
    expected = {item.version: item for item in migrations}
    for version, name, checksum, *_ in rows:
        if version not in expected or version > current:
            raise ValueError('Migration journal conflicts with schema version')
        item = expected[version]
        if name != item.name or checksum != item.checksum:
            raise ValueError(f'Migration {version} checksum mismatch; applied migrations must not be edited')


def migrate_sqlite(connection, migrations=None):
    migrations = SQLITE_MIGRATIONS if migrations is None else migrations
    validate_chain(migrations)
    if connection.in_transaction:
        raise ValueError('Schema migration requires its own transaction')
    with connection:
        connection.execute('BEGIN IMMEDIATE')
        current = connection.execute('PRAGMA user_version').fetchone()[0]
        exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'").fetchone()
        rows = connection.execute('SELECT version,name,checksum,applied_at,adopted FROM schema_migrations ORDER BY version').fetchall() if exists else []
        if exists and current and not rows:
            raise ValueError('Migration journal is incomplete')
        validate_history(current, migrations, rows)
        connection.execute('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY,name TEXT NOT NULL,checksum TEXT NOT NULL,applied_at TEXT NOT NULL,adopted INTEGER NOT NULL CHECK(adopted IN (0,1)))')
        recorded = {row[0] for row in rows}
        applied = []
        for item in migrations:
            adopted = item.version <= current
            if not adopted:
                for statement in item.statements:
                    connection.execute(statement)
                connection.execute(f'PRAGMA user_version={item.version}')
                applied.append(item.version)
            if item.version not in recorded:
                connection.execute('INSERT INTO schema_migrations VALUES (?,?,?,?,?)',
                                   (item.version,item.name,item.checksum,datetime.now(timezone.utc).isoformat(),int(adopted)))
        return applied


def postgres_current(connection):
    if not connection.execute("SELECT to_regclass('cyber_rss.metadata')").fetchone()[0]:
        return 0
    row = connection.execute("SELECT value FROM cyber_rss.metadata WHERE key='schema_version'").fetchone()
    if not row:
        return 0
    try:
        return int(row[0])
    except (ValueError, TypeError):
        raise ValueError('Unsupported PostgreSQL archive schema version')


def migrate_postgres(connection, schema_lock, migrations=None):
    migrations = POSTGRES_MIGRATIONS if migrations is None else migrations
    validate_chain(migrations)
    connection.execute('SELECT pg_advisory_xact_lock(%s)', (schema_lock,))
    current = postgres_current(connection)
    exists = connection.execute("SELECT to_regclass('cyber_rss.schema_migrations')").fetchone()[0]
    rows = connection.execute('SELECT version,name,checksum,applied_at,adopted FROM cyber_rss.schema_migrations ORDER BY version').fetchall() if exists else []
    if exists and current and not rows:
        raise ValueError('Migration journal is incomplete')
    validate_history(current, migrations, rows)
    connection.execute('CREATE SCHEMA IF NOT EXISTS cyber_rss')
    connection.execute('CREATE TABLE IF NOT EXISTS cyber_rss.schema_migrations (version INTEGER PRIMARY KEY,name TEXT NOT NULL,checksum TEXT NOT NULL,applied_at TIMESTAMPTZ NOT NULL,adopted BOOLEAN NOT NULL)')
    recorded = {row[0] for row in rows}
    applied = []
    for item in migrations:
        adopted = item.version <= current
        if not adopted:
            for statement in item.statements:
                connection.execute(statement)
            connection.execute("INSERT INTO cyber_rss.metadata VALUES ('schema_version',%s) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(item.version),))
            applied.append(item.version)
        if item.version not in recorded:
            connection.execute('INSERT INTO cyber_rss.schema_migrations VALUES (%s,%s,%s,%s,%s)',
                               (item.version,item.name,item.checksum,datetime.now(timezone.utc),adopted))
    return applied


def status(current, migrations, rows, backend):
    validate_history(current, migrations, rows)
    return {'backend':backend,'current_version':current,'latest_version':migrations[-1].version,
            'pending':[{'version':item.version,'name':item.name} for item in migrations if item.version>current],
            'history':[{'version':row[0],'name':row[1],'checksum':row[2],
                        'applied_at':row[3].isoformat() if isinstance(row[3],datetime) else row[3],
                        'adopted':bool(row[4])} for row in rows]}
