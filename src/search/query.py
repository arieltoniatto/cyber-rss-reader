from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class FieldQuery:
    include: set[str]
    any_terms: set[str]
    exclude: set[str]


@dataclass(slots=True)
class SearchQuery:
    keyword: set[str] = field(default_factory=set)

    title: set[str] = field(default_factory=set)

    summary: set[str] = field(default_factory=set)

    author: set[str] = field(default_factory=set)

    source: set[str] = field(default_factory=set)

    category: set[str] = field(default_factory=set)

    tags: set[str] = field(default_factory=set)

    any_terms: set[str] = field(default_factory=set)

    exclude: set[str] = field(default_factory=set)