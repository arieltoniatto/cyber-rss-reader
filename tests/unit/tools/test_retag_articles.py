import json
import sqlite3

from enrichment.tag_enricher import TagEnricher
from parser.models import Article
from storage.sqlite_storage import SQLiteArticleRepository
from storage.utils import article_key
from tools.retag_articles import main, retag


def article(title, summary='', tags=(), index=0):
    return Article(title=title, source='Source', summary=summary, url=f'https://example.com/{index}',
                   category='news', tags=list(tags))


def test_retag_removes_only_tags_the_old_substring_rule_explains():
    enricher = TagEnricher()
    # "apt" came from "capture" and "malware" from "Malwarebytes": both are dropped.
    old = article('Capture the flag with Malwarebytes', tags=['apt', 'malware', 'Research'])
    assert retag(old, enricher).tags == ['Research']
    # A keyword tag the old rule cannot explain was supplied by the feed and is kept.
    feed = article('Weekly roundup', tags=['Malware'])
    assert retag(feed, enricher).tags == ['Malware']
    # Current rules add tags the substring rule missed and keep real matches.
    missed = article('APT28 exploited critical vulnerabilities', tags=['exploit', 'apt'])
    assert retag(missed, enricher).tags == ['apt', 'exploit', 'vulnerability']
    assert retag(article('Vazamento de dados', tags=[]), enricher).tags == ['data breach']


def test_command_previews_by_default_and_applies_without_touching_last_seen(tmp_path, monkeypatch, capsys):
    database = tmp_path / 'archive.sqlite3'
    repository = SQLiteArticleRepository(database)
    stale = article('Adapt your capture strategy', tags=['apt'], index=1)
    current = article('Ransomware report', tags=['ransomware'], index=2)
    repository.save([stale, current])

    def seen():
        with sqlite3.connect(database) as connection:
            return connection.execute('SELECT id, first_seen, last_seen, tags FROM articles ORDER BY id').fetchall()

    before = seen()
    monkeypatch.setattr('sys.argv', ['rss-retag', '--database', str(database)])
    main()
    report = json.loads(capsys.readouterr().out)
    assert report['applied'] is False and report['articles'] == 2 and report['changed'] == 1
    assert report['removed'] == {'apt': 1} and report['examples'][0]['title'] == stale.title
    assert seen() == before

    monkeypatch.setattr('sys.argv', ['rss-retag', '--database', str(database), '--apply'])
    main()
    assert json.loads(capsys.readouterr().out)['applied'] is True
    after = seen()
    assert [row[:3] for row in after] == [row[:3] for row in before]
    assert repository.get(article_key(stale)).tags == []
    assert json.loads(dict((row[0], row[3]) for row in after)[article_key(stale)]) == []
    assert repository.get(article_key(current)).tags == ['ransomware']

    monkeypatch.setattr('sys.argv', ['rss-retag', '--database', str(database)])
    main()
    assert json.loads(capsys.readouterr().out)['changed'] == 0


def test_preview_does_not_create_a_missing_database(tmp_path, monkeypatch, capsys):
    database = tmp_path / 'missing.sqlite3'
    monkeypatch.setattr('sys.argv', ['rss-retag', '--database', str(database)])
    main()
    assert json.loads(capsys.readouterr().out)['articles'] == 0
    assert not database.exists()
