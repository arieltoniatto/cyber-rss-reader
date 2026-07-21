from __future__ import annotations

from parser.models import Article

from .filters import apply_filters
from .models import SearchFilters
from .query import SearchQuery
from .utils import fuzzy_contains, searchable_text


class SearchEngine:
    """
    Searches Article collections.
    """

    def search(
        self,
        articles: list[Article],
        query: SearchQuery,
        filters: SearchFilters | None = None,
    ) -> list[Article]:

        matched = []

        for article in articles:

            fields = searchable_text(article)

            values = list(fields.values())

            if not self._include(values, query, filters):
                continue

            if self._excluded(values, query, filters):
                continue

            matched.append(article)

        if filters:
            matched = apply_filters(
                matched,
                filters,
            )

        return matched

    def _include(
        self,
        values: list[str],
        query: SearchQuery,
        filters: SearchFilters | None,
    ) -> bool:

        threshold = (
            filters.fuzzy_threshold
            if filters
            else 80
        )

        for keyword in query.include:

            found = any(
                fuzzy_contains(
                    text,
                    keyword,
                    threshold,
                )
                for text in values
            )

            if not found:
                return False

        if query.optional:

            return any(
                any(
                    fuzzy_contains(
                        text,
                        keyword,
                        threshold,
                    )
                    for text in values
                )
                for keyword in query.optional
            )

        return True

    def _excluded(
        self,
        values: list[str],
        query: SearchQuery,
        filters: SearchFilters | None,
    ) -> bool:

        threshold = (
            filters.fuzzy_threshold
            if filters
            else 80
        )

        for keyword in query.exclude:

            if any(
                fuzzy_contains(
                    text,
                    keyword,
                    threshold,
                )
                for text in values
            ):
                return True

        return False