from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from config.paths import LOG_DIRECTORY


def configure_logging() -> None:
    log_file = LOG_DIRECTORY / "fetch.log"

    handler = RotatingFileHandler(
        log_file,
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )

    handler.setLevel(logging.WARNING)

    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        )
    )

    feed_logger = logging.getLogger("cyber_rss.feeds")

    feed_logger.setLevel(logging.WARNING)
    feed_logger.addHandler(handler)
    feed_logger.propagate = True