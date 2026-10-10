from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_DIRECTORY = Path(__file__).resolve().parent
# Runtime data is independent of the installed package and can be mounted.
RUNTIME_DIRECTORY = Path(os.environ.get("CYBER_RSS_DATA_DIR", str(Path.cwd())))
FEED_DIRECTORY = Path(os.environ.get("CYBER_RSS_FEED_DIR", str(PACKAGE_DIRECTORY / "feeds")))
CATALOG_DIRECTORY = Path(os.environ.get("CYBER_RSS_CATALOG_DIR", str(PACKAGE_DIRECTORY / "catalogs")))
CACHE_DIRECTORY = RUNTIME_DIRECTORY / "cache"
LOG_DIRECTORY = RUNTIME_DIRECTORY / "logs"
DATA_DIRECTORY = RUNTIME_DIRECTORY / "data"
MITRE_ATTACK_DIRECTORY = DATA_DIRECTORY / "mitre-attack"
ARTICLE_CACHE_FILE = CACHE_DIRECTORY / "articles.json"
ARTICLE_DATABASE_FILE = DATA_DIRECTORY / "articles.sqlite3"
BACKUP_DIRECTORY = Path(os.environ.get("CYBER_RSS_BACKUP_DIR", str(DATA_DIRECTORY / "backups")))
APPLICATION_LOG_FILE = LOG_DIRECTORY / "cyber-rss-reader.log"
THREAT_ACTOR_CATALOG_FILE = CATALOG_DIRECTORY / "threat_actors.json"
ATTACK_MAPPING_CATALOG_FILE = CATALOG_DIRECTORY / "attack_mapping.json"
MALWARE_CATALOG_FILE = CATALOG_DIRECTORY / "malware.json"
MISP_GALAXY_DIRECTORY = DATA_DIRECTORY / "misp-galaxy"
MISP_GALAXY_SEED_FILE = CATALOG_DIRECTORY / "misp_threat_actor_galaxy.json"
MISP_GALAXY_SEED_METADATA = CATALOG_DIRECTORY / "misp_threat_actor_galaxy_metadata.json"
THREAT_ACTOR_OVERRIDES_FILE = CATALOG_DIRECTORY / "threat_actor_overrides.json"


def ensure_runtime_directories() -> None:
    for directory in (CACHE_DIRECTORY, LOG_DIRECTORY, DATA_DIRECTORY, MITRE_ATTACK_DIRECTORY):
        directory.mkdir(parents=True, exist_ok=True)
