from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from parser.dates import normalize_datetime
from pathlib import Path

from parser.models import Article

from .exceptions import CacheCorrupted
from .interfaces import ArticleRepository
from .utils import (
    article_from_dict,
    article_key,
    article_to_dict,
)


class JsonArticleRepository(ArticleRepository):
    """
    JSON implementation of ArticleRepository.

    Easily replaceable by SQLite later.
    """

    def __init__(
        self,
        cache_file: Path,
        cache_duration: timedelta,
    ) -> None:

        self.cache_file = cache_file
        self.cache_duration = cache_duration

    def save(self, articles: list[Article]) -> None:

        unique: dict[str, Article] = {}

        for article in articles:
            unique[article_key(article)] = article

        payload = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "articles": [
                article_to_dict(article)
                for article in unique.values()
            ],
        }

        self.cache_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self.cache_file.open(
            "w",
            encoding="utf-8",
        ) as fp:
            json.dump(
                payload,
                fp,
                indent=2,
                ensure_ascii=False,
            )

    def load(self) -> list[Article]:

        if not self.cache_file.exists():
            return []

        try:

            with self.cache_file.open(
                encoding="utf-8"
            ) as fp:

                payload = json.load(fp)

        except json.JSONDecodeError as exc:
            raise CacheCorrupted(
                "Invalid cache file."
            ) from exc

        return [
            article_from_dict(article)
            for article in payload.get("articles", [])
        ]

    def clear(self) -> None:

        if self.cache_file.exists():
            self.cache_file.unlink()

    def refresh(
        self,
        articles: list[Article],
    ) -> None:

        self.save(articles)

    def is_cache_valid(self) -> bool:

        if not self.cache_file.exists():
            return False

        try:
            with self.cache_file.open(
                encoding="utf-8"
            ) as fp:
                payload = json.load(fp)

        except Exception:
            return False

        articles = payload.get("articles", [])

        if not articles:
            return False

        created = normalize_datetime(datetime.fromisoformat(payload["created_at"]))

        expires = created + self.cache_duration

        return datetime.now(timezone.utc) < expires