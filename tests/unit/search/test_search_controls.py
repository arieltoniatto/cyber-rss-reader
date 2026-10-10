from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import typer
from typer.testing import CliRunner

from cli.commands.search import register
from parser.models import Article
from search.engine import SearchEngine
from search.models import SearchFilters
from search.query import SearchQuery
from services.search_service import SearchService


def service(articles):
    return SearchService(repository=SimpleNamespace(load=lambda: articles), engine=SearchEngine())


def article(title, published, tag='research'):
    return Article(title=title, published=published, source='Source', summary='',
                   url=f'https://example.com/{title}', tags=[tag])


@pytest.mark.parametrize('controls', [
    {'limit': 0}, {'limit': -1}, {'limit': True}, {'limit': 1.5},
    {'offset': -1}, {'offset': True}, {'offset': 1.5},
    {'fuzzy_threshold': -1}, {'fuzzy_threshold': 101}, {'fuzzy_threshold': True},
    {'newest': True, 'oldest': True}, {'today': True, 'last_week': True},
    {'match_mode': 'unknown'},
])
def test_invalid_controls_rejected_before_loading_archive(controls):
    search = SearchService(repository=SimpleNamespace(load=lambda: pytest.fail('Invalid request loaded archive')),
                           engine=SearchEngine())
    with pytest.raises(ValueError):
        search.search(**controls)


def test_limit_and_offset_follow_matching_filtering_and_ordering():
    now = datetime.now(timezone.utc)
    articles = [article('Malware old', now - timedelta(days=9)),
                article('Malware yesterday', now - timedelta(days=1)),
                article('Malware now', now), article('Unrelated', now),
                article('Malware other tag', now, 'other')]
    search = service(articles)
    assert [a.title for a in search.search(keyword='malware', tag='research', limit=1, offset=1)] == ['Malware yesterday']
    assert [a.title for a in search.search(keyword='malware', tag='research', oldest=True, limit=1)] == ['Malware old']
    assert search.search(keyword='malware', offset=100) == []
    assert len(SearchEngine().search(articles, SearchQuery(), SearchFilters(offset=2))) == 3


def test_exact_mode_and_threshold_change_matches():
    now = datetime.now(timezone.utc)
    search = service([article('Ransomware report', now)])
    assert search.search(keyword='ransmware', fuzzy_threshold=70)
    assert not search.search(keyword='ransmware', fuzzy_threshold=100)
    assert not search.search(keyword='ransmware', match_mode='exact')
    assert search.search(keyword='RANSOMWARE REPORT', match_mode='exact')
    assert not search.search(any_keywords=['ransmware'], match_mode='exact')
    assert search.search(exclude=['ransmware'], match_mode='exact')


def test_periods_exclude_missing_old_and_future_publications():
    now = datetime.now(timezone.utc)
    search = service([article('Recent', now), article('Old', now - timedelta(days=8)),
                      article('Future', now + timedelta(days=2)), article('Missing', None)])
    assert [a.title for a in search.search(today=True)] == ['Recent']
    assert [a.title for a in search.search(last_week=True)] == ['Recent']


def test_mutated_filters_are_validated_by_engine():
    filters = SearchFilters(limit=1)
    filters.limit = -1
    with pytest.raises(ValueError):
        SearchEngine().search([], SearchQuery(), filters)


def test_cli_controls_apply_to_real_search_results(monkeypatch):
    now = datetime.now(timezone.utc)
    search = service([article('Malware old', now - timedelta(days=2)),
                      article('Malware middle', now - timedelta(days=1)), article('Malware new', now)])
    rendered = []
    monkeypatch.setattr('cli.commands.search.article_table', lambda articles: rendered.extend(a.title for a in articles))
    app = typer.Typer()
    register(app, SimpleNamespace(search_service=search))
    runner = CliRunner()
    result = runner.invoke(app, ['malware', '--limit', '1', '--offset', '1', '--order', 'oldest',
                                 '--period', 'week', '--match', 'exact', '--tag', 'research'])
    assert result.exit_code == 0, result.output
    assert rendered == ['Malware middle']
    for option, value in [('--limit', '0'), ('--offset', '-1'), ('--fuzzy-threshold', '101'),
                          ('--order', 'unknown'), ('--period', 'unknown'), ('--match', 'unknown')]:
        assert runner.invoke(app, ['malware', option, value]).exit_code == 2
    assert rendered == ['Malware middle']
