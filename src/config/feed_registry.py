"""Archive-specific feed settings; SQLite snapshots include all configuration."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from config.loader import ConfigLoader
from config.models import Feed, FeedCategory, FeedConfiguration


class FeedConflict(ValueError):
    pass


class FeedNotFound(LookupError):
    pass


class FeedRegistry:
    KEY = 'managed_feeds'

    def __init__(self, database_file: Path, directory: Path):
        self.database_file = database_file
        self.directory = directory

    def _read(self, connection):
        row = connection.execute('SELECT value FROM metadata WHERE key=?', (self.KEY,)).fetchone()
        if row is not None:
            return json.loads(row[0])
        configuration = ConfigLoader(self.directory).load(include_disabled=True)
        return [{'id': hashlib.sha256(str(feed.url).encode()).hexdigest(),
                 **feed.model_dump(mode='json')} for category in configuration.categories
                for feed in category.feeds]

    def list(self):
        with closing(sqlite3.connect(self.database_file, timeout=30)) as connection:
            return self._read(connection)

    def configuration(self):
        categories = {}
        for row in self.list():
            feed = Feed.model_validate({key: value for key, value in row.items() if key != 'id'})
            if feed.enabled:
                categories.setdefault(feed.category, []).append(feed)
        return FeedConfiguration(source_directory=self.directory, categories=[
            FeedCategory(category=category, feeds=feeds) for category, feeds in categories.items()])

    def save(self, values: dict, *, feed_id: str | None = None):
        with closing(sqlite3.connect(self.database_file, timeout=30)) as connection:
            with connection:
                connection.execute('BEGIN IMMEDIATE')
                rows = self._read(connection)
                if feed_id is not None and not any(row['id'] == feed_id for row in rows):
                    raise FeedNotFound(feed_id)
                for row in rows:
                    if row['id'] != feed_id and (row['name'].casefold() == values['name'].casefold() or
                                                row['url'] == values['url']):
                        raise FeedConflict('Já existe um feed com esse nome ou URL.')
                saved = {'id': feed_id or uuid4().hex, **values}
                rows = [saved if row['id'] == feed_id else row for row in rows]
                if feed_id is None:
                    rows.append(saved)
                connection.execute('INSERT OR REPLACE INTO metadata VALUES (?, ?)',
                                   (self.KEY, json.dumps(rows, ensure_ascii=False)))
                # A changed URL or newly enabled source must not reuse the cache.
                connection.execute("DELETE FROM metadata WHERE key='last_refresh'")
                return saved
