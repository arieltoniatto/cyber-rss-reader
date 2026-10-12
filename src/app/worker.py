from __future__ import annotations

import argparse
import asyncio
import logging
import math
from pathlib import Path

from app.container import ApplicationContainer
from storage.locks import CollectorBusy, collector_lock, worker_instance_lock
from config.paths import ARTICLE_DATABASE_FILE, FEED_DIRECTORY

logger = logging.getLogger(__name__)


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
        container = ApplicationContainer(database_file=args.database,
                                         config_directory=args.feeds, log_level=logging.INFO)
        with worker_instance_lock(container.lock_target):
            asyncio.run(collect(container, interval=args.interval, once=args.once, database_file=container.lock_target))
    except KeyboardInterrupt:
        pass
    except RuntimeError as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
