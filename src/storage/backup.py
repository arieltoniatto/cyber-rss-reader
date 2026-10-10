"""Online SQLite snapshots and non-destructive, verified restores."""
from contextlib import contextmanager, closing
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import uuid

_NAME = re.compile(r"articles-\d{8}T\d{12}Z-[a-f0-9]{8}\.sqlite3$")


@contextmanager
def _backup_lock(directory: Path, *, exclusive: bool):
    with (directory / '.backup.lock').open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def _digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _validate(connection: sqlite3.Connection) -> dict:
    if connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
        raise ValueError('SQLite integrity check failed')
    version = connection.execute('PRAGMA user_version').fetchone()[0]
    if version not in (1, 2):
        raise ValueError(f'Unsupported archive schema: {version}')
    articles = connection.execute('SELECT COUNT(*) FROM articles').fetchone()[0]
    feeds = connection.execute('SELECT COUNT(*) FROM feed_status').fetchone()[0] if version == 2 else 0
    connection.execute('SELECT COUNT(*) FROM metadata').fetchone()
    return {'schema_version': version, 'articles': articles, 'feeds': feeds}


def _snapshot(source: Path, target: Path) -> dict:
    if not source.is_file():
        raise FileNotFoundError(source)
    with closing(sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True, timeout=30)) as origin:
        destination = sqlite3.connect(target)
        try:
            origin.backup(destination, pages=256, sleep=0.1)
            destination.execute('PRAGMA journal_mode=DELETE')
            return _validate(destination)
        finally:
            destination.close()


def _sync_file(path: Path) -> None:
    with path.open('rb') as stream:
        os.fsync(stream.fileno())


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_backup(database: Path, directory: Path, *, keep: int = 14) -> Path:
    if keep < 1:
        raise ValueError('keep must be at least 1')
    if not database.is_file():
        raise FileNotFoundError(database)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _backup_lock(directory, exclusive=True):
        timestamp = datetime.now(timezone.utc)
        name = f"articles-{timestamp.strftime('%Y%m%dT%H%M%S%fZ')}-{uuid.uuid4().hex[:8]}.sqlite3"
        target = directory / name
        with tempfile.NamedTemporaryFile(dir=directory, prefix='.pending-', suffix='.sqlite3', delete=False) as stream:
            pending = Path(stream.name)
        manifest_pending = pending.with_suffix('.json')
        try:
            metrics = _snapshot(database, pending)
            _sync_file(pending)
            manifest = {'created_at': timestamp.isoformat(), 'file': name,
                        'sha256': _digest(pending), **metrics}
            with manifest_pending.open('x', encoding='utf-8') as stream:
                json.dump(manifest, stream, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            manifest_pending.chmod(0o600)
            pending.replace(target)
            manifest_pending.replace(target.with_suffix('.json'))
            _sync_directory(directory)
            # Retention applies only to our complete snapshot/manifest pairs.
            completed = sorted(path for path in directory.glob('articles-*.sqlite3')
                               if _NAME.fullmatch(path.name) and not path.is_symlink()
                               and path.with_suffix('.json').is_file())
            for old in completed[:-keep]:
                old.with_suffix('.json').unlink()
                old.unlink()
            _sync_directory(directory)
            return target
        finally:
            pending.unlink(missing_ok=True)
            manifest_pending.unlink(missing_ok=True)


def restore_backup(backup: Path, output: Path) -> Path:
    """Restore into a NEW file; never overwrite a live archive."""
    output = output.absolute()
    if any(path.exists() for path in (output, Path(str(output) + '-wal'), Path(str(output) + '-shm'))):
        raise FileExistsError(f'Restore destination already exists: {output}')
    with _backup_lock(backup.parent, exclusive=False):
        manifest = json.loads(backup.with_suffix('.json').read_text())
        if manifest.get('file') != backup.name or manifest.get('sha256') != _digest(backup):
            raise ValueError('Backup checksum or manifest does not match')
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix='.restore-', suffix='.sqlite3', delete=False) as stream:
            pending = Path(stream.name)
        try:
            metrics = _snapshot(backup, pending)
            if any(metrics[key] != manifest.get(key) for key in metrics):
                raise ValueError('Backup contents do not match the manifest')
            _sync_file(pending)
            # Exclusive publication also refuses a destination created concurrently.
            os.link(pending, output)
            _sync_directory(output.parent)
        finally:
            pending.unlink(missing_ok=True)
    return output


def _owned_pair(directory: Path, name: str) -> Path:
    if not _NAME.fullmatch(name):
        raise FileNotFoundError(name)
    backup = directory / name
    manifest = backup.with_suffix('.json')
    if any(not path.is_file() or path.is_symlink() for path in (backup, manifest)):
        raise FileNotFoundError(name)
    return backup


def _read_manifest(backup: Path) -> dict:
    manifest = json.loads(backup.with_suffix('.json').read_text())
    if (not isinstance(manifest, dict) or manifest.get('file') != backup.name or
            not isinstance(manifest.get('sha256'), str) or
            not re.fullmatch(r'[a-f0-9]{64}', manifest['sha256']) or
            manifest.get('schema_version') not in (1, 2) or
            any(type(manifest.get(key)) is not int or manifest[key] < 0 for key in ('articles', 'feeds'))):
        raise ValueError('Invalid backup manifest')
    created = datetime.fromisoformat(manifest['created_at'])
    if created.tzinfo is None:
        raise ValueError('Backup timestamp must include a timezone')
    return manifest


def list_backups(directory: Path) -> list[dict]:
    """List only our snapshots, with damaged metadata visible but not downloadable."""
    if not directory.is_dir():
        return []
    rows = []
    with _backup_lock(directory, exclusive=False):
        for path in sorted(directory.glob('articles-*.sqlite3'), reverse=True):
            try:
                backup = _owned_pair(directory, path.name)
            except FileNotFoundError:
                continue
            row = {'id': backup.name, 'size_bytes': backup.stat().st_size,
                   'created_at': None, 'articles': None, 'feeds': None, 'downloadable': False}
            try:
                manifest = _read_manifest(backup)
            except (ValueError, KeyError, TypeError, OSError):
                row['error'] = 'Os metadados desta cópia estão inválidos.'
            else:
                row.update({key: manifest[key] for key in ('created_at', 'articles', 'feeds')})
                row['downloadable'] = True
            rows.append(row)
    return rows


def export_backup(directory: Path, name: str) -> Path:
    """Verify and ZIP a snapshot with its manifest; retention cannot race the copy."""
    from zipfile import ZipFile, ZIP_DEFLATED

    if not directory.is_dir():
        raise FileNotFoundError(name)
    temporary = None
    try:
        with _backup_lock(directory, exclusive=False):
            backup = _owned_pair(directory, name)
            manifest = _read_manifest(backup)
            if _digest(backup) != manifest['sha256']:
                raise ValueError('Backup checksum does not match')
            with closing(sqlite3.connect(backup.resolve().as_uri() + '?mode=ro', uri=True, timeout=30)) as connection:
                metrics = _validate(connection)
            if any(metrics[key] != manifest.get(key) for key in metrics):
                raise ValueError('Backup contents do not match the manifest')
            with tempfile.NamedTemporaryFile(prefix='cyber-rss-backup-', suffix='.zip', delete=False) as stream:
                temporary = Path(stream.name)
            with ZipFile(temporary, 'w', compression=ZIP_DEFLATED) as bundle:
                bundle.write(backup, backup.name)
                bundle.write(backup.with_suffix('.json'), backup.with_suffix('.json').name)
        return temporary
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
