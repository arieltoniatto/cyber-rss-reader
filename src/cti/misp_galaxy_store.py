"""Local Galaxy snapshots with weekly conditional updates and failure-safe replacement."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import tempfile
import time

import httpx
from cti.misp_threat_actors import SOURCE_URL, validate_galaxy

logger = logging.getLogger(__name__)
DEFAULT_INTERVAL_HOURS = 168


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


class MispGalaxyStore:
    MAX_BYTES = 10 * 1024 * 1024
    RETRY_SECONDS = 21600

    def __init__(self, directory: Path, seed_file: Path, seed_metadata: Path, *,
                 interval_hours: float = DEFAULT_INTERVAL_HOURS, transport=None, clock=time.time):
        if not math.isfinite(interval_hours) or interval_hours <= 0:
            raise ValueError('MISP update interval must be positive and finite')
        self.directory = Path(directory)
        self.file = self.directory / 'threat-actor.json'
        self.state_file = self.directory / 'status.json'
        self.seed_file = Path(seed_file)
        self.seed_metadata = Path(seed_metadata)
        self.interval = interval_hours * 3600
        self.transport = transport
        self.clock = clock

    def _read(self, path):
        return validate_galaxy(json.loads(path.read_bytes()))

    def load(self):
        for path in (self.file, self.seed_file):
            try:
                return self._read(path)
            except (OSError, ValueError, TypeError, RecursionError):
                if path.exists():
                    logger.warning('Ignoring invalid MISP Galaxy snapshot: %s', path)
        return None

    def _state(self):
        try:
            state = json.loads(self.state_file.read_bytes())
            if not isinstance(state, dict) or state.get('schema_version') != 1 or state.get('source_url') != SOURCE_URL:
                return {}
            for key in ('checked_at', 'downloaded_at', 'retry_at'):
                value = state.get(key, 0)
                if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                    return {}
            return state
        except (OSError, ValueError, TypeError):
            return {}

    def _save_state(self, state):
        atomic_write(self.state_file, (json.dumps(state, indent=2, ensure_ascii=False) + '\n').encode())

    def status(self):
        state = self._state()
        payload = self.load()
        checked = state.get('checked_at')
        return {'file': str(self.file), 'available': payload is not None, 'version': payload['version'] if payload else None,
                'actors': len(payload['values']) if payload else 0, 'interval_hours': self.interval / 3600,
                'last_checked': datetime.fromtimestamp(checked, timezone.utc).isoformat() if checked else None,
                'next_check': datetime.fromtimestamp(checked + self.interval, timezone.utc).isoformat() if checked else None,
                'last_error': state.get('last_error'), 'source_url': SOURCE_URL}

    @contextmanager
    def _lock(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        with (self.directory / '.update.lock').open('a') as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
                return
            try:
                yield True
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def _seed(self):
        if self.file.exists():
            return
        try:
            data = self.seed_file.read_bytes()
            payload = validate_galaxy(json.loads(data))
            state = json.loads(self.seed_metadata.read_bytes())
            if state.get('sha256') != hashlib.sha256(data).hexdigest() or state.get('source_url') != SOURCE_URL:
                raise ValueError('Invalid seed metadata')
            atomic_write(self.file, data)
            self._save_state({**state, 'schema_version': 1, 'version': payload['version'], 'retry_at': 0})
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            logger.warning('MISP Galaxy seed unavailable; attempting download when due')

    def refresh(self, *, force=False):
        """Never discard a valid local snapshot on failed HTTP/schema validation."""
        try:
            with self._lock() as acquired:
                if not acquired:
                    return 'busy'
                self._seed()
                state = self._state()
                now = self.clock()
                valid_local = False
                try:
                    self._read(self.file)
                    valid_local = state.get('sha256') == hashlib.sha256(self.file.read_bytes()).hexdigest()
                except (OSError, ValueError, TypeError, RecursionError):
                    pass
                if not force and valid_local and now < state.get('checked_at', 0) + self.interval:
                    return 'fresh'
                if not force and now < state.get('retry_at', 0):
                    return 'backoff'
                try:
                    headers = {'Accept': 'application/json', 'User-Agent': 'cyber-rss-reader/misp-galaxy-updater'}
                    if valid_local:
                        for key, header in (('etag', 'If-None-Match'), ('last_modified', 'If-Modified-Since')):
                            value = state.get(key)
                            if isinstance(value, str) and '\n' not in value and '\r' not in value:
                                headers[header] = value
                    with httpx.Client(timeout=httpx.Timeout(15, connect=5), follow_redirects=False,
                                      transport=self.transport, trust_env=False) as client:
                        deadline = time.monotonic() + 30
                        with client.stream('GET', SOURCE_URL, headers=headers) as response:
                            if response.status_code == 304:
                                if not valid_local:
                                    raise ValueError('304 without a valid local snapshot')
                                outcome = 'not_modified'
                            else:
                                response.raise_for_status()
                                data = bytearray()
                                for chunk in response.iter_bytes(chunk_size=65536):
                                    if time.monotonic() > deadline:
                                        raise httpx.ReadTimeout('MISP update deadline exceeded')
                                    data.extend(chunk)
                                    if len(data) > self.MAX_BYTES:
                                        raise ValueError('MISP Galaxy exceeds size limit')
                                payload = validate_galaxy(json.loads(data))
                                atomic_write(self.file, data)
                                state.update(sha256=hashlib.sha256(data).hexdigest(), version=payload['version'],
                                             downloaded_at=now, etag=response.headers.get('etag'),
                                             last_modified=response.headers.get('last-modified'))
                                outcome = 'updated'
                    state.update(schema_version=1, source_url=SOURCE_URL, checked_at=now,
                                 last_attempt=now, retry_at=0, last_error=None)
                    self._save_state(state)
                    return outcome
                except (httpx.HTTPError, OSError, ValueError, TypeError, RecursionError) as exc:
                    logger.warning('MISP update failed; preserving local Galaxy: %s', exc)
                    state.update(schema_version=1, source_url=SOURCE_URL, last_attempt=now,
                                 retry_at=now + self.RETRY_SECONDS, last_error=type(exc).__name__)
                    self._save_state(state)
                    return 'failed'
        except OSError:
            logger.warning('MISP runtime directory unavailable; using packaged snapshot')
            return 'failed'
