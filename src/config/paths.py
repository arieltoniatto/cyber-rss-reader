from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

FEED_DIRECTORY = PROJECT_ROOT / "src" / "config" / "feeds"
CACHE_DIRECTORY = PROJECT_ROOT / "cache"
LOG_DIRECTORY = PROJECT_ROOT / "logs"
DATA_DIRECTORY = PROJECT_ROOT / "data"

ARTICLE_CACHE_FILE = CACHE_DIRECTORY / "articles.json"
APPLICATION_LOG_FILE = LOG_DIRECTORY / "cyber-rss-reader.log"




def ensure_runtime_directories() -> None:
    CACHE_DIRECTORY.mkdir(parents=True, exist_ok=True)
    LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)
    FEED_DIRECTORY.mkdir(parents=True, exist_ok=True)
    DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)