from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SearchOrder(str, Enum):
    newest = "newest"
    oldest = "oldest"


class SearchPeriod(str, Enum):
    all = "all"
    today = "today"
    week = "week"


class SearchMatch(str, Enum):
    fuzzy = "fuzzy"
    exact = "exact"


@dataclass(slots=True)
class SearchFilters:
    """
    Optional filters applied after text matching.
    """

    today: bool = False
    last_week: bool = False

    category: str | None = None
    source: str | None = None
    tag: str | None = None

    newest: bool = False
    oldest: bool = False

    limit: int | None = None

    fuzzy_threshold: int = 80

    offset: int = 0
    match_mode: SearchMatch = SearchMatch.fuzzy

    def __post_init__(self):
        self.validate()

    def validate(self):
        if self.limit is not None and (type(self.limit) is not int or self.limit < 1):
            raise ValueError("limit must be a positive integer")
        if type(self.offset) is not int or self.offset < 0:
            raise ValueError("offset must be a non-negative integer")
        if type(self.fuzzy_threshold) is not int or not 0 <= self.fuzzy_threshold <= 100:
            raise ValueError("fuzzy_threshold must be between 0 and 100")
        if self.newest and self.oldest:
            raise ValueError("Choose either newest or oldest ordering")
        if self.today and self.last_week:
            raise ValueError("Choose either today or last_week")
        if self.match_mode not in (SearchMatch.fuzzy, SearchMatch.exact):
            raise ValueError("match_mode must be fuzzy or exact")
