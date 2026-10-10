"""Run manual collection outside HTTP request threads and share the worker lock."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
import asyncio
import logging
from pathlib import Path
from threading import RLock
from uuid import uuid4

from app.container import ApplicationContainer
from app.worker import collector_lock, CollectorBusy

logger = logging.getLogger(__name__)


def now():
    return datetime.now(timezone.utc).isoformat()


class CollectionController:
    def __init__(self, database_file: Path, service_factory=None):
        self.database_file = database_file
        self.service_factory = service_factory or (lambda: ApplicationContainer(
            database_file=database_file).article_service)
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='rss-collection')
        self.guard = RLock()
        self.state = {'status': 'idle', 'source': None, 'id': None,
                      'started_at': None, 'completed_at': None, 'result': None, 'error': None}

    def status(self):
        with self.guard:
            snapshot = dict(self.state)
            if snapshot['status'] != 'running':
                try:
                    with collector_lock(self.database_file):
                        pass
                except CollectorBusy:
                    return {**snapshot, 'status': 'running', 'source': 'worker',
                            'id': None, 'result': None, 'error': None,
                            'started_at': None, 'completed_at': None}
            return snapshot

    def start(self, *, force_refresh: bool):
        with self.guard:
            if self.state['status'] == 'running':
                raise CollectorBusy('A collection is already running')
            lock = collector_lock(self.database_file)
            lock.__enter__()
            previous = self.state
            self.state = {'status': 'running', 'source': 'manual', 'id': uuid4().hex,
                          'started_at': now(), 'completed_at': None, 'result': None, 'error': None}
            try:
                self.executor.submit(self._run, lock, force_refresh)
            except Exception:
                self.state = previous
                lock.__exit__(None, None, None)
                raise
            return dict(self.state)

    def _run(self, lock, force_refresh):
        outcome = {'status': 'failed', 'result': None,
                   'error': 'A coleta foi interrompida. Tente novamente.'}
        try:
            result = asyncio.run(self.service_factory().update(force_refresh=force_refresh))
            outcome = {'status': 'completed', 'result': asdict(result), 'error': None}
        except Exception:
            logger.exception('Manual collection failed')
            outcome = {'status': 'failed', 'result': None,
                       'error': 'A coleta falhou. Consulte os logs do serviço e tente novamente.'}
        finally:
            with self.guard:
                lock.__exit__(None, None, None)
                self.state.update(outcome, completed_at=now())

    def close(self):
        self.executor.shutdown(wait=True)
