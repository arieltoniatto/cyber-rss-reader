from __future__ import annotations

from datetime import datetime, timedelta, timezone

from parser.models import Article, IOCType

from .models import SearchFilters
from parser.dates import normalize_datetime, publication_key


def apply_filters(
    articles: list[Article],
    filters: SearchFilters,
) -> list[Article]:

    filters.validate()
    result = articles

    now = datetime.now(timezone.utc)

    if filters.today:

        result = [
            article
            for article in result
            if article.published
            and normalize_datetime(article.published).date() == now.date()
        ]

    if filters.last_week:

        cutoff = now - timedelta(days=7)

        result = [
            article
            for article in result
            if article.published
            and cutoff <= normalize_datetime(article.published) <= now
        ]

    if filters.category:

        result = [
            article
            for article in result
            if article.category and article.category.lower()
            == filters.category.lower()
        ]

    if filters.source:

        result = [
            article
            for article in result
            if article.source.lower()
            == filters.source.lower()
        ]

    if filters.newest or filters.oldest:
        result = sorted(result, key=publication_key, reverse=filters.newest)

    if filters.tag:
        result = [a for a in result if any(tag.casefold() == filters.tag.casefold() for tag in a.tags)]

    if filters.threat_actor is not None:
        actor = filters.threat_actor.strip().casefold()
        result = [a for a in result if any(value.casefold() == actor for value in a.threat_actors)]

    if filters.ioc is not None or filters.ioc_type is not None:
        value = filters.ioc.strip() if filters.ioc is not None else None
        result = [a for a in result if any(
            (filters.ioc_type is None or ioc.type == filters.ioc_type)
            and (value is None or (ioc.value == value if ioc.type == IOCType.URL
                                  else ioc.value.casefold() == value.casefold()))
            for ioc in a.iocs
        )]

    if filters.limit is not None:

        result = result[filters.offset:filters.offset + filters.limit]

    else:
        result = result[filters.offset:]

    return result
