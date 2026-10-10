"""Manual snapshots run independently of HTTP requests and feed collection."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
from pathlib import Path
from threading import RLock

from storage.backup import create_backup
from fastapi.responses import FileResponse

logger = logging.getLogger(__name__)


class BackupBusy(RuntimeError):
    pass


class BackupController:
    def __init__(self, database: Path, directory: Path, *, keep: int = 14, creator=create_backup):
        self.database = database
        self.directory = directory
        self.keep = keep
        self.creator = creator
        self.guard = RLock()
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='rss-backup')
        self.state = {'status': 'idle', 'started_at': None, 'completed_at': None,
                      'backup_id': None, 'error': None}

    def status(self):
        with self.guard:
            return dict(self.state)

    def start(self):
        with self.guard:
            if self.state['status'] == 'running':
                raise BackupBusy('A backup is already running')
            previous = self.state
            self.state = {'status': 'running', 'started_at': datetime.now(timezone.utc).isoformat(),
                          'completed_at': None, 'backup_id': None, 'error': None}
            try:
                self.executor.submit(self._run)
            except Exception:
                self.state = previous
                raise
            return dict(self.state)

    def _run(self):
        outcome = {'status': 'failed', 'backup_id': None,
                   'error': 'O backup foi interrompido. Tente novamente.'}
        try:
            path = self.creator(self.database, self.directory, keep=self.keep)
            outcome = {'status': 'completed', 'backup_id': path.name, 'error': None}
        except Exception:
            logger.exception('Manual backup failed')
            outcome = {'status': 'failed', 'backup_id': None,
                       'error': 'Não foi possível gerar o backup. Consulte os logs e tente novamente.'}
        finally:
            with self.guard:
                self.state.update(outcome, completed_at=datetime.now(timezone.utc).isoformat())

    def close(self):
        self.executor.shutdown(wait=True)


class BackupDownloadResponse(FileResponse):
    """Remove the temporary bundle after streaming, including send failures."""
    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            Path(self.path).unlink(missing_ok=True)
