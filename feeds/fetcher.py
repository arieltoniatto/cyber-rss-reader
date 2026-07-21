from __future__ import annotations

import asyncio

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

        self.semaphore = asyncio.Semaphore(concurrency)

    async def fetch_all(self) -> list[FeedResult]:

        tasks = []

        for category in self.configuration.categories:
            for feed in category.feeds:
                tasks.append(self._fetch(feed))

        results = await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )

        successful: list[FeedResult] = []

        for result in results:

            if isinstance(result, FeedResult):
                successful.append(result)

            elif isinstance(result, Exception):
                logger.exception(result)

        return successful

    async def _fetch(
        self,
        feed: Feed,
    ) -> FeedResult | Exception:

        async with self.semaphore:

            try:

                logger.info("Downloading %s", feed.name)

                xml = await self.client.fetch(str(feed.url))

                parsed = feedparser.parse(xml)

                if parsed.bozo:
                    logger.warning(
                        "Feed '%s' contains malformed XML.",
                        feed.name,
                    )

                logger.info("Downloaded %s", feed.name)

                return FeedResult(
                    feed=feed,
                    parsed=parsed,
                )

            except Exception as exc:

                logger.error(
                    "Failed downloading %s (%s)",
                    feed.name,
                    exc,
                )

                return exc