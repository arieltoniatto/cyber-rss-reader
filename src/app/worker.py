from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
import fcntl
import logging
import math
from pathlib import Path

from app.container import ApplicationContainer
from config.paths import ARTICLE_DATABASE_FILE, FEED_DIRECTORY

logger = logging.getLogger(__name__)


class CollectorBusy(RuntimeError):
    pass


@contextmanager
def archive_lock(database_file: Path, suffix: str):
    """The OS releases advisory locks after a process exits."""
    lock_file = database_file.resolve().with_suffix(suffix)
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    with lock_file.open("a") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CollectorBusy("Another collector is already running for this database") from exc
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def collector_lock(database_file: Path):
    return archive_lock(database_file, '.worker.lock')


def worker_instance_lock(database_file: Path):
    return archive_lock(database_file, '.worker-instance.lock')


async def collect(container: ApplicationContainer, *, interval: float, once: bool,
                  database_file: Path = ARTICLE_DATABASE_FILE) -> None:
    while True:
        try:
            with collector_lock(database_file):
                result = await container.article_service.update(force_refresh=True)
            logger.info("Collection result: %s", result)
        except Exception:
            if once:
                raise
            logger.exception("Collection failed; retrying at the next interval")
        if once:
            return
        await asyncio.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect RSS feeds outside the HTTP server.")
    parser.add_argument("--database", type=Path, default=ARTICLE_DATABASE_FILE)
    parser.add_argument("--feeds", type=Path, default=FEED_DIRECTORY)
    parser.add_argument("--interval", type=float, default=21600,
                        help="Seconds between completed collection cycles (default: six hours).")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not math.isfinite(args.interval) or args.interval <= 0:
        parser.error("--interval must be positive")
    try:
        with worker_instance_lock(args.database):
            container = ApplicationContainer(database_file=args.database,
                                             config_directory=args.feeds, log_level=logging.INFO)
            asyncio.run(collect(container, interval=args.interval, once=args.once, database_file=args.database))
    except KeyboardInterrupt:
        pass
    except RuntimeError as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
