from __future__ import annotations

from typing import Iterable

from feeds.models import FeedResult
from parser.utils import parse_published, parse_tags

from .models import Article
from .utils import (
    extract_tags,
    first_available,
    parse_datetime,
)


class RSSParser:
    """
    Converts feedparser results into normalized Article objects.
    """

    def parse(
        self,
        feeds: Iterable[FeedResult],
    ) -> list[Article]:

        articles: list[Article] = []

        for feed in feeds:

            source = (
                feed.parsed.feed.get("title")
                or feed.feed.name
            )

            category = feed.feed.category

            for entry in feed.parsed.entries:

                article = Article(
                    title=first_available(
                        entry,
                        "title",
                    )
                    or "(Untitled)",

                    source=source,

                    category=category,

                    author=first_available(
                        entry,
                        "author",
                        "creator",
                    ),

                    published=parse_published(entry),

                    summary=first_available(
                        entry,
                        "summary",
                        "description",
                    ),

                    url=first_available(
                        entry,
                        "link",
                    )
                    or "",

                    tags=parse_tags(entry),
                )

                articles.append(article)

        return articles