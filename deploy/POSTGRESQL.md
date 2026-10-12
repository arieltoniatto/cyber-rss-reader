# PostgreSQL

SQLite remains the default. PostgreSQL stores articles, collection telemetry,
managed feeds and refresh metadata in the `cyber_rss` schema. The application
initializes schema version 2 transactionally, upgrades version 1 and refuses
unknown versions or changed migration checksums. See the README for
`rss-migrate` and configurable retention.
Use a dedicated database and a role allowed to create its application schema
and tables. PostgreSQL 17 is tested; JSONB, arrays and advisory locks are required.

Install the optional driver:

```bash
.venv/bin/python -m pip install -e '.[web,postgres]'
```

Configure one of `CYBER_RSS_DATABASE_URL` or `CYBER_RSS_DATABASE_URL_FILE` in the
same environment for the CLI, API and worker. A file keeps the connection URL
out of command arguments and is supported by Docker secrets. For example,
create a private, ignored `postgres-url.secret` containing your connection URL:

```text
postgresql://rss:YOUR_URL_ENCODED_PASSWORD@localhost:5432/rss
```

```bash
chmod 600 postgres-url.secret
export CYBER_RSS_DATABASE_URL_FILE="$PWD/postgres-url.secret"
rss-api
rss-worker --interval 21600
# Or use the normal CLI commands:
rss latest --limit 10
rss search ransomware --threat-actor APT28
```

Passwords in connection URLs must be percent-encoded when they contain URL
reserved characters. SSL/query parameters accepted by psycopg/libpq, such as
`sslmode=verify-full`, can be included. Do not commit connection strings or
secret files. For user services, add the file variable to `.env.services` and
restart API/worker after installing the optional dependency.

`--database` continues to set the SQLite path and the nearby local runtime
storage location. With a PostgreSQL URL configured it does not select SQLite;
unset both URL variables to return to SQLite. An explicit programmatic
`database_url=''` also selects SQLite. Existing JSON-cache adapters remain
available when explicitly selected.

Each repository operation opens its own connection and commits/rolls back as a
unit. Refresh preserves history unless optional age/size retention is enabled. Complete
article payloads (IOCs, malware, actors, ATT&CK and CVEs) are preserved in JSONB.
Publication times use `TIMESTAMPTZ`; missing dates sort last. Filtering keeps
Python casefold semantics and uses indexed source/category fields and tag arrays.
A fixed-size SHA-256 key allows arbitrarily long source URLs while preserving the
original article IDs returned by the API. Search and topic extraction retain the
existing application algorithms; PostgreSQL full-text search is not introduced.

Collector and worker-instance locks use PostgreSQL session advisory locks,
shared by different app processes connecting to the same database. Feed
configuration updates are serialized transactionally. Use direct PostgreSQL
connections or a proxy with session pooling: transaction pooling does not
preserve the session lock contract. Connections close after each operation;
collector locks hold a dedicated connection for the duration of the collection.

CVE lookup caching and the MISP Galaxy remain local runtime data. Keep the
runtime directory persistent (and mount it in Docker) independently of the
PostgreSQL database. PostgreSQL support does not make these caches stateless.

## Import an existing SQLite archive

The import is explicit; selecting PostgreSQL does not migrate or delete SQLite
files. Validate the original archive first:

```bash
rss-import-postgres --sqlite data/articles.sqlite3 --dry-run
```

Stop collection against the source archive before the final import, so that no
new records are missed during the cutover. With the PostgreSQL destination URL
configured, run:

```bash
rss-import-postgres --sqlite data/articles.sqlite3
```

The tool opens SQLite read-only and copies articles, first/last seen timestamps,
feed outcomes, managed-feed settings and refresh metadata into one PostgreSQL
transaction. The destination must be empty. It refuses to overwrite existing
history/configuration and rolls back if validation or any insert fails.
Repeating an import of the same source snapshot is a no-op. The source archive
is retained; after validation, use the same PostgreSQL URL for API, CLI and worker.
To roll back, stop the PostgreSQL collector and unset the URL variables; the
original SQLite archive is still available but will not contain changes made
only in PostgreSQL after cutover.

## Docker

The application image includes the PostgreSQL driver. The existing
`compose.yaml` remains the SQLite deployment. `compose.postgres.yaml` is a
separate stack with API, worker, PostgreSQL 17 and persistent volumes. It uses
file secrets, does not publish the database port, and publishes the interface
on host loopback as before.

Create two private files outside Git: `postgres-password.secret` containing the
raw database password, and `postgres-url.secret` containing
`postgresql://rss:URL_ENCODED_PASSWORD@database:5432/rss`. Set their absolute paths:

```bash
export CYBER_RSS_POSTGRES_PASSWORD_FILE="$PWD/postgres-password.secret"
export CYBER_RSS_DATABASE_URL_FILE="$PWD/postgres-url.secret"
docker compose -f compose.postgres.yaml up --build -d
```

The application runs as UID 10001, so grant that runtime user read access to
mounted secret files. Docker Compose file-backed secrets preserve the host file
permissions; do not rely on a `mode` setting to change those permissions
([Docker Compose secrets documentation](https://docs.docker.com/reference/compose-file/services/#secrets)).
The PostgreSQL initialization password is applied only to a new database volume;
changing the secret does not rotate an existing database role's password.
Use a separate Compose project name if running both example stacks at once.

## Backups

The web SQLite snapshot/download controls are unavailable for PostgreSQL and
show guidance for external database backups. `rss-backup` and the SQLite backup
worker reject implicit use while a PostgreSQL URL is configured; specifying
`--database` explicitly still permits backing up an old SQLite archive.

Use provider backups or PostgreSQL tools. In the PostgreSQL Compose stack:

```bash
docker compose -f compose.postgres.yaml exec -T database \
  pg_dump -U rss -d rss -Fc > rss-postgres.dump
```

Restore using `pg_restore` into a separate database and verify it before switching
the application's URL. The existing SQLite restore utility accepts SQLite
snapshots, not PostgreSQL dumps. Plan PostgreSQL backup scheduling/retention
separately; the PostgreSQL example stack intentionally has no SQLite backup worker.

## Tests

Use a dedicated, disposable database: these tests clear application tables and
metadata in the configured test database. This variable is separate from the
application's database configuration:

```bash
CYBER_RSS_TEST_POSTGRES_URL=postgresql://USER:PASSWORD@localhost:5432/rss_test \
  .venv/bin/python -m pytest tests/postgres -q
```

When that test URL is absent, PostgreSQL tests are skipped. SQLite unit/browser
coverage remains available without a PostgreSQL server or the optional driver.
