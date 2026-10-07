"""Periodically create verified snapshots without requiring systemd or cron."""
import argparse
import logging
import math
from pathlib import Path
import signal
import sqlite3
from threading import Event

from config.paths import ARTICLE_DATABASE_FILE, BACKUP_DIRECTORY
from storage.backup import create_backup

logger = logging.getLogger(__name__)


def run_backups(database: Path, directory: Path, *, interval: float, retry: float,
                keep: int, stop: Event, backup=create_backup) -> None:
    while not stop.is_set():
        try:
            path = backup(database, directory, keep=keep)
        except (OSError, ValueError, sqlite3.Error):
            logger.exception('Backup failed; retrying in %s seconds', retry)
            delay = retry
        else:
            logger.info('Backup verified: %s', path)
            delay = interval
        stop.wait(delay)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, default=ARTICLE_DATABASE_FILE)
    parser.add_argument('--directory', type=Path, default=BACKUP_DIRECTORY)
    parser.add_argument('--interval', type=float, default=86400)
    parser.add_argument('--retry', type=float, default=300)
    parser.add_argument('--keep', type=int, default=14)
    args = parser.parse_args()
    if any(not math.isfinite(value) or value <= 0 for value in (args.interval, args.retry)) or args.keep < 1:
        parser.error('Intervals and retention must be positive')
    logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
    stop = Event()
    for name in (signal.SIGTERM, signal.SIGINT):
        signal.signal(name, lambda *_: stop.set())
    run_backups(args.database, args.directory, interval=args.interval, retry=args.retry,
                keep=args.keep, stop=stop)


if __name__ == '__main__':
    main()
