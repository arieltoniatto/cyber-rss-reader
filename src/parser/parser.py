from __future__ import annotations

from typing import Iterable
import re
from urllib.parse import urlsplit

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

            source = feed.feed.name

            category = feed.feed.category

            feed_url = urlsplit(str(feed.feed.url))
            sans_diaries = (
                feed_url.hostname == "isc.sans.edu"
                and feed_url.path in {"/rssfeed.xml", "/rssfeed_full.xml"}
            )

            for entry in feed.parsed.entries:

                title = first_available(entry, "title") or "(Untitled)"
                # Stormcast announcements also appear in the diary feed, with
                # different URLs from the dedicated podcast feed.
                if sans_diaries and re.match(r"^(?:ISC|SANS)\s+Stormcast\b", title, re.IGNORECASE):
                    continue

                article = Article(
                    title=title,

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
                    ) or "",

                    url=first_available(
                        entry,
                        "link",
                    )
                    or "",

                    tags=parse_tags(entry),
                )

                articles.append(article)

        return articles
