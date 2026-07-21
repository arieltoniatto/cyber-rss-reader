from __future__ import annotations

from datetime import datetime, timedelta

from parser.models import Article

from .models import SearchFilters


def apply_filters(
    articles: list[Article],
    filters: SearchFilters,
) -> list[Article]:

    result = articles

    now = datetime.now().astimezone()

    if filters.today:

        result = [
            article
            for article in result
            if article.published
            and article.published.date() == now.date()
        ]

    if filters.last_week:

        cutoff = now - timedelta(days=7)

        result = [
            article
            for article in result
            if article.published
            and article.published >= cutoff
        ]

    if filters.category:

        result = [
            article
            for article in result
            if article.category.lower()
            == filters.category.lower()
        ]

    if filters.source:

        result = [
            article
            for article in result
            if article.source.lower()
            == filters.source.lower()
        ]

    if filters.newest:

        result.sort(
            key=lambda x: x.published or datetime.min,
            reverse=True,
        )

    elif filters.oldest:

        result.sort(
            key=lambda x: x.published or datetime.min,
        )

    if filters.limit is not None:

        result = result[: filters.limit]

    return result