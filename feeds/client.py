from __future__ import annotations

import asyncio

import httpx

from .exceptions import FeedFetchError


class RSSHttpClient:
    """
    Small reusable HTTP client responsible only for downloading
    feed contents.
    """

    def __init__(
        self,
        *,
        timeout: float = 15.0,
        retries: int = 3,
        user_agent: str = "CyberRSSReader/1.0",
    ) -> None:

        self.timeout = timeout
        self.retries = retries
        self.user_agent = user_agent

    async def fetch(self, url: str) -> bytes:

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/rss+xml, application/xml, text/xml",
        }

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers=headers,
        ) as client:

            last_exception: Exception | None = None

            for attempt in range(1, self.retries + 1):

                try:

                    response = await client.get(url)

                    response.raise_for_status()

                    return response.content

                except (
                    httpx.TimeoutException,
                    httpx.TransportError,
                    httpx.HTTPStatusError,
                ) as exc:

                    last_exception = exc

                    if attempt < self.retries:
                        await asyncio.sleep(attempt)

            raise FeedFetchError(str(last_exception))