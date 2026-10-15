import csv
import io
import json
from types import SimpleNamespace

import typer
from typer.testing import CliRunner

from cli.commands.export import register
from parser.models import Article, IOC, IOCType
from search.engine import SearchEngine
from services.export_service import export_articles
from services.search_service import SearchService
from storage.sqlite_storage import SQLiteArticleRepository


def article(title='Report'):
    return Article(title=title, source='Source', summary='Line one, accented: ação\nLine two.',
                   url='https://example.com/report', tags=['research'], threat_actors=['APT28'],
                   iocs=[IOC(IOCType.CVE, 'CVE-2026-1234')])


def test_json_and_jsonl_preserve_full_structured_metadata():
    exported = json.loads(export_articles([article()]))
    assert exported['schema_version'] == 1 and exported['count'] == 1
    row = exported['articles'][0]
    assert row['summary'] == article().summary
    assert row['iocs'] == [{'type': 'cve', 'value': 'CVE-2026-1234'}]
    assert row['threat_actors'] == ['APT28'] and row['id']
    assert json.loads(export_articles([article()], 'jsonl')) == row
    assert json.loads(export_articles([]))['articles'] == []
    assert export_articles([], 'jsonl') == ''


def test_csv_quotes_newlines_and_neutralizes_formulas():
    for title in ['=CMD()', ' \t+CMD()', '-123', '@SUM(1)']:
        rows = list(csv.DictReader(io.StringIO(export_articles([article(title)], 'csv'))))
        assert rows[0]['title'] == "'"+title
        assert rows[0]['summary'] == article().summary
        assert json.loads(rows[0]['iocs'])[0]['type'] == 'cve'
    assert len(list(csv.reader(io.StringIO(export_articles([], 'csv'))))) == 1


def test_cli_export_filters_writes_and_never_overwrites(tmp_path):
    repo = SQLiteArticleRepository(tmp_path/'archive.sqlite3')
    repo.save([article()])
    app = typer.Typer()
    register(app, SimpleNamespace(search_service=SearchService(repository=repo, engine=SearchEngine())))
    runner = CliRunner()
    path = tmp_path/'articles.jsonl'
    args = ['--format', 'jsonl', '--threat-actor', 'apt28', '--output', str(path)]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert json.loads(path.read_text())['title'] == 'Report'
    assert runner.invoke(app, args).exit_code != 0
    assert runner.invoke(app, ['--limit', '10001']).exit_code != 0
    empty = runner.invoke(app, ['--source', 'missing'])
    assert empty.exit_code == 0 and json.loads(empty.output)['count'] == 0
