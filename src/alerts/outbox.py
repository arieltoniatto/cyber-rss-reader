"""Transactional outbox in shared archive metadata, including durable delivery receipts."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import time
import uuid

from services.export_service import record
from storage.utils import article_key

PREFIX = 'alerts:v1:'
LOCK = 73941107


def sql_names(backend):
    return ('cyber_rss.metadata', '%s') if backend == 'postgresql' else ('metadata', '?')


def enqueue(connection, articles, settings, backend):
    if settings is None or not settings.active:
        return
    table, mark = sql_names(backend)
    if backend == 'postgresql':
        connection.execute('SELECT pg_advisory_xact_lock(%s)', (LOCK,))
    for article in {article_key(item): item for item in articles}.values():
        identifier = article_key(article)
        if backend == 'postgresql':
            exists = connection.execute('SELECT 1 FROM cyber_rss.articles WHERE key_hash=%s',
                                        (hashlib.sha256(identifier.encode()).digest(),)).fetchone()
        else:
            exists = connection.execute('SELECT 1 FROM articles WHERE id=?', (identifier,)).fetchone()
        if exists:
            continue
        for destination in settings.active:
            if not destination.rules.matches(article):
                continue
            event_id = hashlib.sha256((destination.id+'\0'+identifier).encode()).hexdigest()
            exported = record(article)
            exported['summary'] = article.summary[:600] if destination.include_summary else ''
            event = {'schema_version': 1, 'id': event_id, 'type': 'article.created',
                     'created_at': datetime.now(timezone.utc).isoformat(), 'article': exported}
            state = {'destination': destination.id, 'event': event, 'state': 'pending',
                     'attempts': 0, 'next_attempt': 0, 'lease_until': 0, 'lease_token': None}
            connection.execute(f'INSERT INTO {table} (key,value) VALUES ({mark},{mark}) ON CONFLICT(key) DO NOTHING',
                               (PREFIX+event_id, json.dumps(state, ensure_ascii=False)))


class AlertOutbox:
    def __init__(self, repository):
        if not hasattr(repository, '_connection'):
            raise ValueError('Alerts require SQLite or PostgreSQL storage')
        self.repository = repository
        self.backend = getattr(repository, 'backend', 'sqlite')
        self.table, self.mark = sql_names(self.backend)

    @contextmanager
    def transaction(self):
        with self.repository._connection() as connection:
            if self.backend == 'postgresql':
                connection.execute('SELECT pg_advisory_xact_lock(%s)', (LOCK,))
            else:
                connection.execute('BEGIN IMMEDIATE')
            yield connection

    def rows(self, connection):
        return [(key, json.loads(value)) for key, value in connection.execute(
            f'SELECT key,value FROM {self.table} WHERE key LIKE {self.mark} ORDER BY key', (PREFIX+'%',)).fetchall()]

    def write(self, connection, key, state):
        connection.execute(f'UPDATE {self.table} SET value={self.mark} WHERE key={self.mark}',
                           (json.dumps(state, ensure_ascii=False), key))

    def status(self):
        counts = dict.fromkeys(('pending', 'sending', 'sent', 'failed'), 0)
        errors = []
        with self.repository._connection() as connection:
            for key, state in self.rows(connection):
                counts[state['state']] += 1
                if state.get('last_error'):
                    errors.append({'id': key[len(PREFIX):], 'destination': state['destination'],
                                   'error': state['last_error']})
        return {**counts, 'errors': errors[:20]}

    def claim(self, settings, now=None):
        now = time.time() if now is None else now
        active = {item.id for item in settings.active}
        with self.transaction() as connection:
            for key, state in self.rows(connection):
                if state['destination'] not in active or state['state'] in ('sent', 'failed'):
                    continue
                if state['lease_until'] > now or state['next_attempt'] > now:
                    continue
                if state['attempts'] >= settings.max_attempts:
                    state['state'] = 'failed'
                    state['last_error'] = 'Delivery lease expired after final attempt'
                    self.write(connection, key, state)
                    continue
                state.update(state='sending', attempts=state['attempts']+1, lease_until=now+120,
                             lease_token=uuid.uuid4().hex)
                self.write(connection, key, state)
                return key, state
        return None

    def finish(self, key, claimed, *, error=None, max_attempts=3, now=None):
        now = time.time() if now is None else now
        with self.transaction() as connection:
            row = connection.execute(f'SELECT value FROM {self.table} WHERE key={self.mark}', (key,)).fetchone()
            state = json.loads(row[0]) if row else None
            if not state or state['lease_token'] != claimed['lease_token']:
                return
            state.update(lease_until=0, lease_token=None)
            if error:
                state.update(state='failed' if state['attempts'] >= max_attempts else 'pending',
                             next_attempt=now+min(3600, 60*2**(state['attempts']-1)), last_error=error)
            else:
                state.update(state='sent', sent_at=datetime.now(timezone.utc).isoformat(), last_error=None)
                # Keep only a compact receipt, so retention/reimports cannot resend it.
                state['event'] = {'id': state['event']['id']}
            self.write(connection, key, state)

    def retry_failed(self):
        with self.transaction() as connection:
            count = 0
            for key, state in self.rows(connection):
                if state['state'] == 'failed':
                    state.update(state='pending', attempts=0, next_attempt=0, last_error=None)
                    self.write(connection, key, state)
                    count += 1
            return count
