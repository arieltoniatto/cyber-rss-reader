from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class SearchFilters:
    """
    Optional filters applied after text matching.
    """

    today: bool = False
    last_week: bool = False

    category: str | None = None
    source: str | None = None

    newest: bool = False
    oldest: bool = False

    limit: int | None = None

    fuzzy_threshold: int = 80