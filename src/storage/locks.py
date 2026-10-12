"""File and PostgreSQL collector locks, shared by CLI, worker and API."""
from contextlib import contextmanager
import fcntl
from pathlib import Path


class CollectorBusy(RuntimeError):
    pass


@contextmanager
def archive_lock(database, suffix):
    if hasattr(database,'advisory_lock'):
        with database.advisory_lock('worker-instance' if suffix=='.worker-instance.lock' else 'collector'):
            yield
        return
    lock_file=Path(database).resolve().with_suffix(suffix)
    lock_file.parent.mkdir(parents=True,exist_ok=True)
    with lock_file.open('a') as stream:
        try:
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CollectorBusy('Another collector is already running for this database') from exc
        try:
            yield
        finally:
            fcntl.flock(stream,fcntl.LOCK_UN)


def collector_lock(database):
    return archive_lock(database,'.worker.lock')


def worker_instance_lock(database):
    return archive_lock(database,'.worker-instance.lock')
