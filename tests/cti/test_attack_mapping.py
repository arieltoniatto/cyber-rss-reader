from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer
from typer.testing import CliRunner

from cti.attack_mapping import AttackCatalog, build_attack_mapping_catalog
from enrichment.attack_enricher import AttackEnricher
from parser.models import Article, AttackMapping
from search.engine import SearchEngine
from services.search_service import SearchService
from services.attack_service import AttackService
from storage.json_storage import JsonArticleRepository
from storage.sqlite_storage import SQLiteArticleRepository
from storage.utils import article_to_dict, article_from_dict
from cli.commands.attack import register


@pytest.fixture
def bundle():
    def node(kind, identifier, name, **kwargs):
        return dict(type=kind, id=kind + '--' + identifier, name=name,
                    external_references=[{'source_name': 'mitre-attack', 'external_id': identifier}], **kwargs)
    nodes = [node('intrusion-set', 'G0001', 'SeedActor'), node('malware', 'S0001', 'SeedWare'),
             node('tool', 'S0002', 'OtherTool'), node('attack-pattern', 'T1059', 'Command Interpreter'),
             node('attack-pattern', 'T1059.001', 'PowerShell', x_mitre_is_subtechnique=True,
                  kill_chain_phases=[{'kill_chain_name': 'mitre-attack', 'phase_name': 'execution'}]),
             node('attack-pattern', 'T1111', 'Other Technique'), node('attack-pattern', 'T2222', 'Campaign Technique'),
             node('campaign', 'C0001', 'Operation Alpha', aliases=['Alpha Wave', 'Shared Operation']),
             node('campaign', 'C0002', 'Operation Beta', aliases=['Shared Operation'])]
    ids = {n['external_references'][0]['external_id']: n['id'] for n in nodes}
    def edge(identifier, kind, source, target):
        return dict(type='relationship', id='relationship--' + identifier, relationship_type=kind,
                    source_ref=ids[source], target_ref=ids[target], description=identifier + ' evidence')
    return {'objects': nodes + [edge('group-ware', 'uses', 'G0001', 'S0001'),
                               edge('ware-tech', 'uses', 'S0001', 'T1059.001'),
                               edge('sub-parent', 'subtechnique-of', 'T1059.001', 'T1059'),
                               edge('group-tech', 'uses', 'G0001', 'T1111'),
                               edge('campaign-group', 'attributed-to', 'C0001', 'G0001'),
                               edge('campaign-tool', 'uses', 'C0001', 'S0002'),
                               edge('tool-tech', 'uses', 'S0002', 'T2222')]}


@pytest.fixture
def catalog(bundle):
    return AttackCatalog(build_attack_mapping_catalog(bundle, attack_version='19.1', source_url='fixture.json'))


def article(text='', **kwargs):
    return Article(title='Report', source='Source', summary=text, url='https://example.com/report', **kwargs)


def test_builder_excludes_latest_revoked_deprecated_dangling_and_unsupported_edges(bundle):
    old = next(n for n in bundle['objects'] if n['id'] == 'attack-pattern--T1111')
    old['modified'] = '2025-01-01T00:00:00Z'
    bundle['objects'].extend([{**old, 'modified': '2026-01-01T00:00:00Z', 'revoked': True},
                              {'type': 'relationship', 'id': 'relationship--dangling', 'relationship_type': 'uses',
                               'source_ref': 'intrusion-set--G0001', 'target_ref': 'malware--missing'},
                              {'type': 'relationship', 'id': 'relationship--invalid', 'relationship_type': 'uses',
                               'source_ref': [], 'target_ref': 'malware--S0001'}])
    next(n for n in bundle['objects'] if n['id'] == 'campaign--C0002')['x_mitre_deprecated'] = True
    next(n for n in bundle['objects'] if n['id'] == 'relationship--campaign-tool')['revoked'] = True
    payload = build_attack_mapping_catalog(bundle, attack_version='19.1', source_url='fixture')
    assert {'T1111', 'C0002'}.isdisjoint({n['id'] for n in payload['entities']})
    assert {'relationship--group-tech', 'relationship--dangling', 'relationship--invalid',
            'relationship--campaign-tool'}.isdisjoint({e['id'] for e in payload['relationships']})


@pytest.mark.parametrize('text,techniques,campaigns', [
    ('T1059.001. C0001.', ['T1059.001'], ['C0001']),
    ('t1059.001 C0001', ['T1059.001'], ['C0001']),
    ('PowerShell commands are listed.', [], []),
    ('Operation Alpha is reported.', [], ['C0001']),
    ('alpha wave is reported.', [], ['C0001']),
    ('Shared Operation was reported.', [], []),
    ('Alpha Wave.test is a hostname.', [], []),
    ('T1059.0010 T1059.00 prefixT1059 T9999 C9999', [], []),
    ('https://example.com/T1059.001/Operation-Alpha', [], []),
    ('https://attack.mitre.org/techniques/T1059/001/', ['T1059.001'], []),
    ('https://attack.mitre.org.evil.test/techniques/T1059/001/', [], []),
    ('https://attack.mitre.org/campaigns/C0001/', [], ['C0001']),
    ('https://attack.mitre.org/groups/T1059/', [], []),
])
def test_detects_explicit_ids_and_unambiguous_campaign_names(catalog, text, techniques, campaigns):
    mapping = catalog.detect(article(text))
    assert mapping.technique_ids == techniques
    assert mapping.campaign_ids == campaigns


def test_group_context_is_not_article_technique_or_campaign_attribution(catalog):
    mapping = catalog.detect(article(threat_actors=['SeedActor']))
    assert mapping.entity_ids == ['G0001']
    assert mapping.technique_ids == [] and mapping.campaign_ids == []
    details = catalog.describe(mapping)
    assert {n['id'] for n in details['techniques']} == {'T1059', 'T1059.001', 'T1111'}
    assert all(n['basis'] == 'catalog' for n in details['techniques'] + details['campaigns'])
    assert {n['id'] for n in details['campaigns']} == {'C0001'}
    assert all(edge['basis'] == 'catalog' for edge in details['relationships'])
    assert 'relationship--campaign-tool' not in {e['id'] for e in details['relationships']}
    assert 'relationship--sub-parent' in {e['id'] for e in details['relationships']}


def test_campaign_context_does_not_expand_inferred_group_profile(catalog):
    mapping = catalog.detect(article('C0001'))
    details = catalog.describe(mapping)
    assert [(n['id'], n['basis']) for n in details['campaigns']] == [('C0001', 'article')]
    assert {n['id'] for n in details['techniques']} == {'T2222'}
    assert 'relationship--campaign-group' in {e['id'] for e in details['relationships']}
    assert 'relationship--group-tech' not in {e['id'] for e in details['relationships']}


def test_direct_technique_does_not_reverse_infer_actor(catalog):
    mapping = catalog.detect(article('T1111'))
    details = catalog.describe(mapping)
    assert [(n['id'], n['basis']) for n in details['techniques']] == [('T1111', 'article')]
    assert details['relationships'] == []
    assert details['campaigns'] == []


def test_malware_context_and_direct_subtechnique_have_separate_provenance(catalog):
    mapping = catalog.detect(article('T1059.001', malware=['seedware']))
    assert mapping.entity_ids == ['S0001', 'T1059.001']
    assert [(n['id'], n['basis']) for n in catalog.describe(mapping)['techniques']] == [('T1059', 'catalog'), ('T1059.001', 'article')]


@pytest.mark.parametrize('backend', ['sqlite', 'json'])
@pytest.mark.asyncio
async def test_mapping_round_trip_is_compact_backward_compatible_and_idempotent(catalog, backend, tmp_path):
    repo = (SQLiteArticleRepository(tmp_path / 'archive.sqlite3') if backend == 'sqlite' else
            JsonArticleRepository(tmp_path / 'archive.json', timedelta(hours=6)))
    original = article('T1059.001 Operation Alpha', threat_actors=['SeedActor'], malware=['SeedWare'])
    enriched = await AttackEnricher(catalog).enrich(original)
    assert original.attack is None
    repo.save([enriched])
    loaded = repo.load()[0]
    assert loaded == enriched
    assert await AttackEnricher(catalog).enrich(loaded) == loaded
    assert len(json.dumps(article_to_dict(loaded)['attack'])) < 300
    legacy = article_to_dict(original); legacy.pop('attack')
    assert article_from_dict(legacy).attack is None
    assert catalog.describe(replace(loaded.attack, catalog_version='older'))['status'] == 'version_mismatch'
    assert catalog.describe(replace(loaded.attack, catalog_version='older'))['relationships'] == []


@pytest.mark.asyncio
async def test_missing_catalog_preserves_existing_mapping():
    original = article(attack=AttackMapping('19.1', entity_ids=['T1059']))
    assert await AttackEnricher(None).enrich(original) is original


@pytest.mark.parametrize('payload', [None, [], {'schema_version': 2},
                                     {'schema_version': 1, 'metadata': {}, 'entities': [], 'relationships': []}])
def test_bad_catalog_load_is_safe_no_op(tmp_path, payload):
    path = tmp_path / 'catalog.json'; path.write_text(json.dumps(payload))
    assert AttackCatalog.load(path) is None


def test_duplicate_external_ids_are_rejected(bundle):
    obj = next(n for n in bundle['objects'] if n['id'] == 'attack-pattern--T1059')
    bundle['objects'].append({**obj, 'id': 'attack-pattern--duplicate'})
    with pytest.raises(ValueError, match='Duplicate'):
        build_attack_mapping_catalog(bundle, attack_version='19.1', source_url='fixture')


def test_cli_exposes_article_and_catalog_context_without_rewriting_archive(catalog, tmp_path):
    repo = SQLiteArticleRepository(tmp_path / 'archive.sqlite3')
    repo.save([article('T1059.001 Operation Alpha')])
    service = AttackService(SearchService(repository=repo, engine=SearchEngine()), catalog)
    app = typer.Typer(); register(app, SimpleNamespace(attack_service=service))
    runner = CliRunner()
    result = runner.invoke(app, ['report', '--limit', '1', '--max-relations', '1'])
    assert result.exit_code == 0, result.output
    assert 'Article references' in result.output
    assert 'Related catalog context' in result.output
    assert 'T1059.001' in result.output and 'C0001' in result.output
    assert 'not article assertions' in result.output
    assert repo.load()[0].attack is None
    assert runner.invoke(app, ['report', '--limit', '0']).exit_code == 2


def test_updater_builds_atomically_and_rejects_overwriting_bundle(bundle, tmp_path, monkeypatch):
    from tools.update_attack_catalog import main
    source = tmp_path / 'enterprise-attack-19.1.json'; source.write_text(json.dumps(bundle))
    output = tmp_path / 'catalog.json'
    monkeypatch.setattr('sys.argv', ['rss-update-attack', '--input', str(source), '--output', str(output)])
    main()
    assert AttackCatalog.load(output).version == '19.1'
    before = output.read_bytes()
    source.write_text(json.dumps({'objects': None}))
    with pytest.raises(ValueError): main()
    assert output.read_bytes() == before
    monkeypatch.setattr('sys.argv', ['rss-update-attack', '--input', str(source), '--output', str(source)])
    with pytest.raises(SystemExit): main()


def test_campaign_alias_shared_with_actor_is_not_an_explicit_campaign_mention(bundle):
    next(n for n in bundle['objects'] if n['id'] == 'campaign--C0001')['aliases'].append('SeedActor')
    catalog = AttackCatalog(build_attack_mapping_catalog(bundle, attack_version='19.1', source_url='fixture'))
    mapping = catalog.detect(article('SeedActor', threat_actors=['SeedActor']))
    assert mapping.campaign_ids == []
    assert mapping.entity_ids == ['G0001']
    assert catalog.detect(article('C0001')).campaign_ids == ['C0001']


def test_catalog_links_are_built_from_validated_ids(bundle):
    payload = build_attack_mapping_catalog(bundle, attack_version='19.1', source_url='fixture')
    for node in payload['entities']:
        node['url'] = 'javascript:alert(1)'
    catalog = AttackCatalog(payload)
    assert all(node['url'].startswith('https://attack.mitre.org/') for node in catalog.entities.values())


@pytest.mark.asyncio
async def test_default_collection_pipeline_persists_mapping_and_backup_restores_it(tmp_path):
    import feedparser
    from unittest.mock import AsyncMock
    from app.container import ApplicationContainer
    from config.models import Feed
    from feeds.models import FeedResult
    from storage.backup import create_backup, restore_backup

    feeds = tmp_path / 'feeds'; feeds.mkdir()
    (feeds / 'news.yaml').write_text('category: news\nfeeds:\n  - name: Source\n    url: https://example.com/rss\n')
    container = ApplicationContainer(database_file=tmp_path / 'archive.sqlite3', config_directory=feeds)
    parsed = feedparser.parse(b'''<rss version="2.0"><channel><title>Source</title><item>
    <title>APT28 BlackEnergy T1059.001</title><description>Campaign C0001</description>
    <link>https://example.com/mapping</link></item></channel></rss>''')
    container.fetcher.fetch_all = AsyncMock(return_value=[FeedResult(feed=Feed(name='Source', url='https://example.com/rss', category='news'), parsed=parsed)])
    result = await container.article_service.update(force_refresh=True)
    assert result.articles_saved == 1
    saved = container.repository.load()[0]
    assert saved.attack.catalog_version == '19.1'
    assert saved.attack.technique_ids == ['T1059.001']
    assert saved.attack.campaign_ids == ['C0001']
    assert 'G0007' in saved.attack.entity_ids
    assert 'BlackEnergy' in saved.malware
    snapshot = create_backup(container.repository.database_file, tmp_path / 'backups')
    restored = restore_backup(snapshot, tmp_path / 'restored.sqlite3')
    assert SQLiteArticleRepository(restored).load()[0] == saved
