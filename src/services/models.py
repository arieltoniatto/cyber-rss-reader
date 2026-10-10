from __future__ import annotations

from dataclasses import dataclass
from parser.models import IOCType


@dataclass(slots=True, frozen=True)
class UpdateResult:
    """
    Result returned by ArticleService.update().
    """


    feeds_downloaded: int
    articles_parsed: int
    articles_saved: int
    cache_used: bool
    feeds_failed: int = 0

@dataclass(slots=True, frozen=True)
class LatestQuery:
    category: str | None = None
    source: str | None = None
    tag: str | None = None
    limit: int = 20
    offset: int = 0
    ioc: str | None = None
    ioc_type: IOCType | None = None
    threat_actor: str | None = None
