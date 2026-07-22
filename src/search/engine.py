from __future__ import annotations

from parser.models import Article

from .filters import apply_filters
from .models import SearchFilters
from .query import SearchQuery
from .utils import fuzzy_contains, searchable_fields


class SearchEngine:

    def search(
        self,
        articles: list[Article],
        query: SearchQuery,
        filters: SearchFilters | None = None,
    ) -> list[Article]:

        matched = []

        for article in articles:

            fields = searchable_fields(article)

            if not self._matches(fields, query, filters):
                continue

            matched.append(article)

        if filters:
            matched = apply_filters(
                matched,
                filters,
            )

        return matched

    def _matches(
        self,
        fields: dict[str, str],
        query: SearchQuery,
        filters: SearchFilters | None,
    ) -> bool:

        threshold = (
            filters.fuzzy_threshold
            if filters
            else 80
        )

        #######################################################
        # AND searches
        #######################################################

        mapping = {
            "keyword": query.keyword,
            "title": query.title,
            "summary": query.summary,
            "author": query.author,
            "source": query.source,
            "category": query.category,
            "tags": query.tags,
        }

        for field, keywords in mapping.items():

            text = fields[field]

            for keyword in keywords:

                if not fuzzy_contains(
                    text,
                    keyword,
                    threshold,
                ):
                    return False

        #######################################################
        # OR
        #######################################################

        if query.any_terms:

            combined = " ".join(fields.values())

            if not any(
                fuzzy_contains(
                    combined,
                    keyword,
                    threshold,
                )
                for keyword in query.any_terms
            ):
                return False

        #######################################################
        # NOT
        #######################################################

        if query.exclude:

            combined = " ".join(fields.values())

            for keyword in query.exclude:

                if fuzzy_contains(
                    combined,
                    keyword,
                    threshold,
                ):
                    return False

        return True