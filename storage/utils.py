from __future__ import annotations

from dataclasses import asdict
from datetime import datetime

from parser.models import Article


def article_key(article: Article) -> str:
    """
    Stable key used for deduplication.

    URL is preferred because it is typically unique.
    """
    return article.url.strip().lower()


def article_to_dict(article: Article) -> dict:
    data = asdict(article)

    if article.published is not None:
        data["published"] = article.published.isoformat()

    return data


def article_from_dict(data: dict) -> Article:
    published = data.get("published")

    if published:
        published = datetime.fromisoformat(published)

    return Article(
        title=data["title"],
        source=data["source"],
        category=data["category"],
        author=data.get("author"),
        published=published,
        summary=data.get("summary"),
        url=data["url"],
        tags=data.get("tags", []),
    )