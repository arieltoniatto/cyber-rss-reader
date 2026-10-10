import pytest

from enrichment.ioc_enricher import IOCEnricher
from parser.models import Article, IOC, IOCType


def article(summary='', **kwargs):
    return Article(title='Report', source='Source', summary=summary,
                   url='https://publisher.test/news', **kwargs)


@pytest.mark.asyncio
async def test_refangs_validates_and_normalizes_all_observable_types():
    summary = ('hxxps://EVIL[.]test/Case?q=AbC user[@]evil[.]test 203[.]0[.]113[.]10 '
               '2001:0db8::1 ::ffff:192.0.2.1 evil[.]test '
               + 'A' * 32 + ' ' + 'B' * 40 + ' ' + 'C' * 64
               + ' cve-2026-12345678 as00123')
    original = article(summary)
    enriched = await IOCEnricher().enrich(original)
    assert set(enriched.iocs) == {
        IOC(IOCType.URL, 'https://evil.test/Case?q=AbC'), IOC(IOCType.DOMAIN, 'evil.test'),
        IOC(IOCType.EMAIL, 'user@evil.test'), IOC(IOCType.IPV4, '203.0.113.10'),
        IOC(IOCType.IPV6, '2001:db8::1'), IOC(IOCType.IPV6, '::ffff:c000:201'),
        IOC(IOCType.MD5, 'a' * 32), IOC(IOCType.SHA1, 'b' * 40), IOC(IOCType.SHA256, 'c' * 64),
        IOC(IOCType.CVE, 'CVE-2026-12345678'), IOC(IOCType.ASN, 'AS123'),
    }
    assert original.iocs == []
    assert await IOCEnricher().enrich(enriched) == enriched


@pytest.mark.parametrize('kind,value', [
    (IOCType.IPV4, '999.1.2.3'), (IOCType.IPV6, '2001:db8::xyz'),
    (IOCType.DOMAIN, '-bad.test'), (IOCType.DOMAIN, 'bad..test'),
    (IOCType.DOMAIN, 'x' * 64 + '.test'), (IOCType.DOMAIN, 'bad_domain.test'),
    (IOCType.EMAIL, '.user@evil.test'), (IOCType.EMAIL, 'a..b@evil.test'),
    (IOCType.EMAIL, 'user@-evil.test'), (IOCType.EMAIL, 'user@evil..test'),
    (IOCType.MD5, 'a' * 31), (IOCType.SHA1, 'z' * 40), (IOCType.SHA256, 'a' * 65),
    (IOCType.CVE, 'CVE-26-1234'), (IOCType.CVE, 'CVE-2026-123'),
    (IOCType.ASN, 'AS0'), (IOCType.ASN, 'AS4294967296'),
    (IOCType.URL, 'javascript:alert(1)'), (IOCType.URL, 'https:///path'),
    (IOCType.URL, 'https://evil..test/path'), (IOCType.URL, 'https://evil.test:65536/'),
    (IOCType.URL, 'https://evil.test:abc/'), (IOCType.URL, 'https://evil.test/bad path'),
    (IOCType.URL, 'https://evil.test/\npath'), (IOCType.URL, 'https://evil.test\\path'),
    ('unknown', 'anything'), (IOCType.DOMAIN, None),
])
@pytest.mark.asyncio
async def test_invalid_existing_iocs_are_removed(kind, value):
    enriched = await IOCEnricher().enrich(article(iocs=[IOC(kind, value)]))
    assert enriched.iocs == []


@pytest.mark.asyncio
async def test_urls_preserve_path_query_case_and_balanced_delimiters():
    original = article('(https://EVIL.test/a(b)). https://evil.test/Case?q=AbC https://evil.test/case?q=abc '
                       'https://[2001:db8::1]/a https://evil.zip/path')
    enriched = await IOCEnricher().enrich(original)
    urls = {ioc.value for ioc in enriched.iocs if ioc.type == IOCType.URL}
    assert urls == {'https://evil.test/a(b)', 'https://evil.test/Case?q=AbC',
                    'https://evil.test/case?q=abc', 'https://[2001:db8::1]/a', 'https://evil.zip/path'}
    assert IOC(IOCType.IPV6, '2001:db8::1') in enriched.iocs
    assert IOC(IOCType.DOMAIN, 'evil.zip') in enriched.iocs


@pytest.mark.asyncio
async def test_ignores_paths_file_names_versions_and_partial_tokens():
    original = article('https://evil.test/tools/sample.exe/path.fake/news.test/1.2.3.4 '
                       'first.last@evil.test sample.exe config.json report.pdf '
                       '-bad.test bad..test bad_domain.test 1.2.3.4.5 version 1.2.3.4 '
                       '999.1.2.3 2001:db8::xyz prefixCVE-2026-1234 CVE-2026-1234-suffix '
                       'AS4294967296 x' + 'a' * 32 + 'g')
    enriched = await IOCEnricher().enrich(original)
    assert {ioc.value for ioc in enriched.iocs if ioc.type == IOCType.DOMAIN} == {'evil.test'}
    assert not any(ioc.type in (IOCType.IPV4, IOCType.IPV6, IOCType.CVE, IOCType.ASN, IOCType.MD5) for ioc in enriched.iocs)


@pytest.mark.asyncio
async def test_keeps_private_ips_and_publisher_url_is_not_extracted():
    enriched = await IOCEnricher().enrich(article('IP:10.0.0.1 ::1 CVE-2026-1234'))
    assert IOC(IOCType.IPV4, '10.0.0.1') in enriched.iocs
    assert IOC(IOCType.IPV6, '::1') in enriched.iocs
    assert not any(ioc.type in (IOCType.URL, IOCType.DOMAIN) for ioc in enriched.iocs)


@pytest.mark.asyncio
async def test_normalization_deduplicates_hosts_but_preserves_distinct_url_case():
    original = article(iocs=[IOC(IOCType.URL, 'HTTPS://EVIL.test/Case'),
                             IOC(IOCType.URL, 'https://evil.test/Case'),
                             IOC(IOCType.URL, 'https://evil.test/case'),
                             IOC(IOCType.DOMAIN, 'EVIL.TEST.'),
                             IOC(IOCType.DOMAIN, 'evil.test')])
    result = await IOCEnricher().enrich(original)
    assert result.iocs == [IOC(IOCType.URL, 'https://evil.test/Case'),
                           IOC(IOCType.URL, 'https://evil.test/case'),
                           IOC(IOCType.DOMAIN, 'evil.test')]


@pytest.mark.asyncio
async def test_sentence_punctuation_does_not_hide_valid_network_indicators():
    enriched = await IOCEnricher().enrich(article('IP 203.0.113.10. Domain evil.test. Email user@evil.test.'))
    assert set(enriched.iocs) == {IOC(IOCType.IPV4, '203.0.113.10'),
                                 IOC(IOCType.DOMAIN, 'evil.test'), IOC(IOCType.EMAIL, 'user@evil.test')}
