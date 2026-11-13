from __future__ import annotations

import asyncio

import httpx

from .exceptions import FeedFetchError
from .network import Resolver, private_feeds_allowed, request_guard, system_resolver


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
        allow_private_networks: bool | None = None,
        resolver: Resolver = system_resolver,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:

        self.timeout = timeout
        self.retries = retries
        self.user_agent = user_agent
        self.allow_private_networks = (private_feeds_allowed() if allow_private_networks is None
                                       else allow_private_networks)
        self.resolver = resolver
        self.transport = transport

    async def fetch(self, url: str) -> bytes:

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/rss+xml, application/xml, text/xml",
        }

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers=headers,
            transport=self.transport,
            event_hooks={"request": [] if self.allow_private_networks else [request_guard(self.resolver)]},
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