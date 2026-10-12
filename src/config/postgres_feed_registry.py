"""PostgreSQL-backed feed settings using the same validation and YAML defaults."""
import json
from config.feed_registry import FeedRegistry
from storage.postgres_storage import LOCK_KEYS


class PostgreSQLFeedRegistry(FeedRegistry):
    def __init__(self, repository, directory):
        self.repository=repository
        self.directory=directory

    def _read(self, connection):
        row=connection.execute('SELECT value FROM cyber_rss.metadata WHERE key=%s',(self.KEY,)).fetchone()
        if row:
            return json.loads(row[0])
        return self._defaults()

    def list(self):
        with self.repository._connection() as connection:
            return self._read(connection)

    def save(self, values, *, feed_id=None):
        with self.repository._connection() as connection:
            connection.execute('SELECT pg_advisory_xact_lock(%s)',(LOCK_KEYS['feed-registry'],))
            rows=self._read(connection)
            saved,rows=self._updated_rows(rows,values,feed_id)
            self.repository._set_metadata(connection,self.KEY,json.dumps(rows,ensure_ascii=False))
            connection.execute("DELETE FROM cyber_rss.metadata WHERE key='last_refresh'")
            return saved
