from pathlib import Path
import sqlite3

from tools.backup_worker import run_backups


def test_failed_backup_retries_then_uses_daily_interval_and_stops(caplog):
    calls = []
    class Stop:
        delays = []
        def is_set(self):
            return len(self.delays) == 2
        def wait(self, seconds):
            self.delays.append(seconds)
    stop = Stop()
    def backup(database, directory, *, keep):
        calls.append((database, directory, keep))
        if len(calls) == 1:
            raise sqlite3.OperationalError('temporarily locked')
        return directory / 'snapshot.sqlite3'
    run_backups(Path('archive.sqlite3'), Path('backups'), interval=86400, retry=300,
                keep=14, stop=stop, backup=backup)
    assert stop.delays == [300, 86400]
    assert len(calls) == 2
    assert 'Backup failed' in caplog.text


def test_already_stopped_worker_does_not_create_snapshot():
    from threading import Event
    stop = Event()
    stop.set()
    def unexpected(*args, **kwargs):
        raise AssertionError('Stopped worker attempted a backup')
    run_backups(Path('archive.sqlite3'), Path('backups'), interval=86400, retry=300,
                keep=14, stop=stop, backup=unexpected)
