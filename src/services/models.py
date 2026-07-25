from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class UpdateResult:
    """
    Result returned by ArticleService.update().
    """
    

    feeds_downloaded: int
    articles_parsed: int
    articles_saved: int
    cache_used: bool

@dataclass(slots=True, frozen=True)
class LatestQuery:
    category: str | None = None
    source: str | None = None
    tag: str | None = None
    limit: int = 20