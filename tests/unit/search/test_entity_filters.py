from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import typer
from typer.testing import CliRunner

from cli.commands.latest import register as register_latest
from cli.commands.search import register as register_search
from parser.models import Article, IOC, IOCType
from search.engine import SearchEngine
from services.article_service import ArticleService
from services.models import LatestQuery
from services.search_service import SearchService
from storage.json_storage import JsonArticleRepository
from storage.sqlite_storage import SQLiteArticleRepository


@pytest.fixture(params=['sqlite', 'json'])
def services(request, tmp_path):
    repo = (SQLiteArticleRepository(tmp_path / 'archive.sqlite3') if request.param == 'sqlite' else
            JsonArticleRepository(tmp_path / 'archive.json', timedelta(hours=6)))
    def article(name, day, actors, iocs):
        return Article(title=f'Report {name}', source='Source', summary='APT28 CVE-2026-1234',
                       category='news', tags=['research'], url=f'https://example.com/{name}',
                       published=datetime(2026, 1, day, tzinfo=timezone.utc),
                       threat_actors=actors, iocs=iocs)
    cve = IOC(IOCType.CVE, 'CVE-2026-1234')
    repo.save([
        article('A', 1, ['APT28'], [cve, IOC(IOCType.DOMAIN, 'evil.test'),
                                  IOC(IOCType.URL, 'https://evil.test/Case'),
                                  IOC(IOCType.IPV4, '203.0.113.1')]),
        article('E', 2, ['APT28'], [cve]),
        article('F', 3, ['APT280'], []),
        article('D', 4, ['APT28'], [IOC(IOCType.CVE, 'CVE-2026-9999')]),
        article('C', 5, ['APT29'], [cve]),
        article('B', 6, [], []),
    ])
    return SimpleNamespace(repository=repo,
        search_service=SearchService(repository=repo, engine=SearchEngine()),
        article_service=ArticleService(repository=repo, fetcher=None, parser=None, enrichment_pipeline=None))


def titles(rows):
    return [a.title for a in rows]


@pytest.mark.parametrize('filters,expected', [
    ({'threat_actor': ' apt28 '}, ['Report D', 'Report E', 'Report A']),
    ({'threat_actor': 'APT2'}, []),
    ({'ioc': 'cve-2026-1234'}, ['Report C', 'Report E', 'Report A']),
    ({'ioc_type': IOCType.CVE}, ['Report C', 'Report D', 'Report E', 'Report A']),
    ({'ioc': 'CVE-2026'}, []),
    ({'ioc': 'CVE-2026-1234', 'ioc_type': IOCType.CVE, 'threat_actor': 'apt28'}, ['Report E', 'Report A']),
    ({'ioc': 'https://evil.test/Case', 'ioc_type': IOCType.IPV4}, []),
    ({'ioc': 'https://evil.test/Case', 'ioc_type': IOCType.URL}, ['Report A']),
    ({'ioc': 'https://evil.test/case'}, []),
    ({'ioc': 'EVIL.TEST', 'ioc_type': IOCType.DOMAIN}, ['Report A']),
    ({'threat_actor': 'Unknown'}, []),
])
@pytest.mark.asyncio
async def test_filters_use_enriched_entities_and_same_indicator(services, filters, expected):
    assert titles(services.search_service.search(keyword='report', **filters)) == expected
    assert titles(await services.article_service.latest(LatestQuery(**filters))) == expected


@pytest.mark.asyncio
async def test_entity_filters_combine_with_metadata_before_pagination(services):
    controls = dict(ioc='CVE-2026-1234', threat_actor='APT28', category='NEWS',
                    source='SOURCE', tag='RESEARCH', limit=1, offset=1)
    assert titles(services.search_service.search(keyword='report', **controls)) == ['Report A']
    assert titles(await services.article_service.latest(LatestQuery(**controls))) == ['Report A']
    assert titles(services.search_service.search(keyword='report', oldest=True, **controls)) == ['Report E']
    assert not services.search_service.search(keyword='unrelated', match_mode='exact', **controls)
    assert not services.search_service.search(keyword='report', ioc_type='cve', tag='missing')


@pytest.mark.parametrize('filters', [{'ioc': ''}, {'ioc': '  '}, {'ioc': 123},
                                    {'threat_actor': ''}, {'threat_actor': '  '}, {'ioc_type': 'unknown'}])
@pytest.mark.asyncio
async def test_invalid_entity_filters_rejected_by_both_services(filters):
    repo = SimpleNamespace(load=lambda: pytest.fail('Invalid filter loaded archive'))
    search = SearchService(repository=repo, engine=SearchEngine())
    latest = ArticleService(repository=repo, fetcher=None, parser=None, enrichment_pipeline=None)
    with pytest.raises(ValueError):
        search.search(**filters)
    with pytest.raises(ValueError):
        await latest.latest(LatestQuery(**filters))


def test_cli_filters_use_services_and_validate_values(services, monkeypatch):
    rendered = []
    for command in ('search', 'latest'):
        monkeypatch.setattr(f'cli.commands.{command}.article_table', lambda rows: rendered.append(titles(rows)))
    app = typer.Typer()
    register_search(app, services)
    register_latest(app, services)
    runner = CliRunner()
    for command in (['search', 'report'], ['latest']):
        options = ['--ioc', ' cve-2026-1234 ', '--ioc-type', 'cve', '--threat-actor', ' apt28 ',
                   '--category', 'news', '--source', 'Source', '--tag', 'research', '--limit', '1']
        result = runner.invoke(app, command + options)
        assert result.exit_code == 0, result.output
        assert rendered[-1] == ['Report E']
        result = runner.invoke(app, command + ['--ioc-type', 'domain'])
        assert result.exit_code == 0, result.output
        assert rendered[-1] == ['Report A']
        for invalid in (['--ioc-type', 'unknown'], ['--ioc', ' '], ['--threat-actor', '']):
            count = len(rendered)
            result = runner.invoke(app, command + invalid)
            assert result.exit_code == 2, result.output
            assert len(rendered) == count


@pytest.mark.asyncio
async def test_sqlite_latest_without_entity_filters_keeps_sql_path(tmp_path, monkeypatch):
    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    repo.save([Article(title='Report B', source='Source', summary='', url='https://example.com/B')])
    latest = ArticleService(repository=repo, fetcher=None, parser=None, enrichment_pipeline=None)
    monkeypatch.setattr(repo, 'load', lambda: pytest.fail('Unfiltered latest loaded archive'))
    assert titles(await latest.latest(LatestQuery(limit=1))) == ['Report B']
