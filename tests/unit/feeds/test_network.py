import asyncio
import socket

import httpx
import pytest

from feeds.client import RSSHttpClient
from feeds.exceptions import FeedFetchError
from feeds.network import UnsafeFeedURL, ensure_public_url, is_public_address, obviously_private_host

RSS = b'<rss version="2.0"><channel><title>Test</title></channel></rss>'


def resolver_for(*addresses):
    async def resolve(host, port):
        return list(addresses)
    return resolve


@pytest.mark.parametrize('address', ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254',
                                     '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', 'fe80::1', 'fd00::1',
                                     '::ffff:127.0.0.1', '::ffff:10.0.0.1'])
def test_non_public_addresses_are_blocked(address):
    assert not is_public_address(address)


@pytest.mark.parametrize('address', ['93.184.216.34', '8.8.8.8', '2606:4700:4700::1111'])
def test_public_addresses_are_allowed(address):
    assert is_public_address(address)


@pytest.mark.parametrize('host, private', [('localhost', True), ('Feeds.LocalHost.', True), ('127.0.0.1', True),
                                           ('[::1]', True), ('example.com', False), ('8.8.8.8', False)])
def test_obviously_private_host_needs_no_dns(host, private):
    assert obviously_private_host(host) is private


@pytest.mark.parametrize('answer', [('10.0.0.7',), ('93.184.216.34', '127.0.0.1'), ()])
def test_hostnames_resolving_to_private_or_no_addresses_are_blocked(answer):
    with pytest.raises(UnsafeFeedURL):
        asyncio.run(ensure_public_url(httpx.URL('https://feeds.example/rss'), resolver_for(*answer)))


def test_public_hostname_and_scheme_checks():
    asyncio.run(ensure_public_url(httpx.URL('https://feeds.example/rss'), resolver_for('93.184.216.34')))
    with pytest.raises(UnsafeFeedURL, match='scheme'):
        asyncio.run(ensure_public_url(httpx.URL('ftp://feeds.example/rss'), resolver_for('93.184.216.34')))


def test_redirect_to_metadata_server_is_blocked_before_it_is_requested():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={'Location': 'http://169.254.169.254/computeMetadata/v1/'})

    client = RSSHttpClient(retries=1, allow_private_networks=False, transport=httpx.MockTransport(handler))
    with pytest.raises(UnsafeFeedURL):
        asyncio.run(client.fetch('https://93.184.216.34/feed'))
    assert seen == ['https://93.184.216.34/feed']


def test_redirect_to_hostname_resolving_privately_is_blocked():
    def handler(request):
        if request.url.host == '93.184.216.34':
            return httpx.Response(301, headers={'Location': 'https://internal.example/feed'})
        raise AssertionError('internal host must not be requested')

    async def resolve(host, port):
        return ['10.10.0.4'] if host == 'internal.example' else ['93.184.216.34']

    client = RSSHttpClient(retries=1, allow_private_networks=False, resolver=resolve,
                           transport=httpx.MockTransport(handler))
    with pytest.raises(UnsafeFeedURL, match='internal.example'):
        asyncio.run(client.fetch('https://93.184.216.34/feed'))


def test_public_feed_is_downloaded_and_private_feed_allowed_only_when_enabled(monkeypatch):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=RSS))
    public = RSSHttpClient(retries=1, allow_private_networks=False, transport=transport)
    assert asyncio.run(public.fetch('https://93.184.216.34/feed')) == RSS
    with pytest.raises(UnsafeFeedURL):
        asyncio.run(public.fetch('http://192.168.1.20/feed'))
    monkeypatch.setenv('CYBER_RSS_ALLOW_PRIVATE_FEEDS', '1')
    lan = RSSHttpClient(retries=1, transport=transport)
    assert asyncio.run(lan.fetch('http://192.168.1.20/feed')) == RSS


def test_dns_failure_is_a_normal_retryable_fetch_error():
    async def failing(host, port):
        raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')

    client = RSSHttpClient(retries=2, allow_private_networks=False, resolver=failing,
                           transport=httpx.MockTransport(lambda request: httpx.Response(200, content=RSS)))
    with pytest.raises(FeedFetchError) as error:
        asyncio.run(client.fetch('https://missing.example/feed'))
    assert not isinstance(error.value, UnsafeFeedURL)
