"""Outbound address policy for feed downloads (SSRF protection).

Feed URLs can be edited through the web API, so every request the collector
makes, including each redirect hop, must target a public internet address.
Set ``CYBER_RSS_ALLOW_PRIVATE_FEEDS=1`` to collect from feeds hosted on a
private network (for example a LAN-only deployment).
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from collections.abc import Awaitable, Callable, Iterable

import httpx

from .exceptions import FeedFetchError

ALLOW_PRIVATE_ENV = "CYBER_RSS_ALLOW_PRIVATE_FEEDS"

Resolver = Callable[[str, int], Awaitable[Iterable[str]]]


class UnsafeFeedURL(FeedFetchError):
    """The feed URL points to a destination the collector must not reach."""


def private_feeds_allowed() -> bool:
    return os.environ.get(ALLOW_PRIVATE_ENV, "").strip().lower() in {"1", "true", "yes"}


def is_public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def literal_address(host: str) -> str | None:
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        return None


def obviously_private_host(host: str) -> bool:
    """Cheap check without DNS, used to reject feed URLs when they are saved."""
    name = host.strip("[]").rstrip(".").lower()
    if name == "localhost" or name.endswith(".localhost"):
        return True
    address = literal_address(name)
    return address is not None and not is_public_address(address)


async def system_resolver(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


async def ensure_public_url(url: httpx.URL, resolver: Resolver = system_resolver) -> None:
    if url.scheme not in {"http", "https"}:
        raise UnsafeFeedURL(f"Blocked feed URL scheme: {url.scheme}")
    host = url.host
    if not host:
        raise UnsafeFeedURL("Feed URL has no host")
    if obviously_private_host(host):
        raise UnsafeFeedURL(f"Blocked non-public feed destination: {host}")
    if literal_address(host) is not None:
        return
    port = url.port or (443 if url.scheme == "https" else 80)
    addresses = list(await resolver(host, port))
    if not addresses:
        raise UnsafeFeedURL(f"Feed host did not resolve: {host}")
    # Any private answer is rejected, so a mixed DNS answer cannot be used to
    # reach an internal service.
    blocked = [address for address in addresses if not is_public_address(address)]
    if blocked:
        raise UnsafeFeedURL(f"Blocked non-public feed destination: {host} -> {blocked[0]}")


def request_guard(resolver: Resolver = system_resolver):
    """httpx request hook; httpx runs it for every request, redirects included."""
    async def guard(request: httpx.Request) -> None:
        try:
            await ensure_public_url(request.url, resolver)
        except OSError as exc:
            raise httpx.ConnectError(f"Could not resolve {request.url.host}: {exc}", request=request) from exc
    return guard
