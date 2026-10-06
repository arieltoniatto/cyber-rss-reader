from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import feedparser

from config.models import Feed, FeedConfiguration

from .client import RSSHttpClient
from .logger import logger
from .models import FeedResult


class RSSFetcher:
    """
    Downloads and parses RSS feeds concurrently.

    Responsibilities:

    - download feeds
    - parse XML
    - log failures
    - never raise because one feed failed
    """

    def __init__(
        self,
        configuration: FeedConfiguration,
        *,
        timeout: float = 15,
        retries: int = 3,
        concurrency: int = 20,
        user_agent: str = "CyberRSSReader/1.0",
    ) -> None:

        self.configuration = configuration

        self.client = RSSHttpClient(
            timeout=timeout,
            retries=retries,
            user_agent=user_agent,
        )

        self.concurrency = concurrency

    async def fetch_all(self) -> list[FeedResult]:

        tasks = []
        semaphore = asyncio.Semaphore(self.concurrency)

        for category in self.configuration.categories:

            for feed in category.feeds:
                tasks.append(self._fetch(feed, semaphore))

        results = await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )

        outcomes: list[FeedResult] = []

        for result in results:

            if isinstance(result, FeedResult):
                outcomes.append(result)

            elif isinstance(result, Exception):
                logger.error("Feed collection failed: %s", result)

        return outcomes

    async def _fetch(
        self,
        feed: Feed,
        semaphore: asyncio.Semaphore,
    ) -> FeedResult:

        async with semaphore:
            attempted_at = datetime.now(timezone.utc)

            try:

                logger.info("Downloading %s", feed.name)

                xml = await self.client.fetch(str(feed.url))

                parsed = feedparser.parse(xml)
                if not parsed.version:
                    raise ValueError("Response is not an RSS/Atom feed")

                warnings: list[str] = []

                if parsed.bozo:
                    message = (
                        f"Feed '{feed.name}' contains malformed XML.\n"
                        f"Reason: {parsed.bozo_exception}"
                    )

                    logger.warning(message)

                    warnings.append(message)

                logger.info("Downloaded %s", feed.name)

                return FeedResult(
                    feed=feed,
                    parsed=parsed,
                    warnings=warnings,
                    attempted_at=attempted_at,
                )

            except Exception as exc:

                logger.error(
                    "Failed downloading %s (%s)",
                    feed.name,
                    exc,
                )

                return FeedResult(
                    feed=feed, parsed=feedparser.FeedParserDict(entries=[]),
                    error=f"{type(exc).__name__}: {exc}", attempted_at=attempted_at,
                )
