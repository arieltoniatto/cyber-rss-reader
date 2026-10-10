from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from cti.misp_galaxy_store import MispGalaxyStore
from cti.misp_threat_actors import GALAXY_UUID, SOURCE_URL, merge_actors, validate_galaxy
from enrichment.threat_actor_enricher import ThreatActorEnricher
from parser.models import Article


def cluster(name, aliases=(), **meta):
    return {'uuid': str(uuid4()), 'value': name, 'meta': {'synonyms': list(aliases), **meta}}


@pytest.fixture
def galaxy():
    return {'uuid': GALAXY_UUID, 'type': 'threat-actor', 'version': 1,
            'values': [cluster('Mapped Actor', ['APT28', 'Fighting Ursa', 'G0007']),
                       cluster('New Cyber Group', ['New Alias', 'Silence']),
                       cluster('Other Group', ['Shared Alias']), cluster('Third Group', ['Shared Alias']),
                       cluster('A Campaign', **{'threat-actor-classification': ['campaign']}),
                       cluster('An Operation', **{'threat-actor-classification': ['operation']})]}


@pytest.fixture
def mitre():
    return [{'name': 'APT28', 'attack_id': 'G0007', 'stix_id': 'intrusion-set--one', 'aliases': ['Fancy Bear']},
            {'name': 'APT29', 'attack_id': 'G0016', 'stix_id': 'intrusion-set--two', 'aliases': ['Cozy Bear']}]


@pytest.fixture
def setup_store(tmp_path, galaxy):
    clock = [1000000.0]
    seed = tmp_path / 'seed.json'
    data = json.dumps(galaxy).encode()
    seed.write_bytes(data)
    meta = tmp_path / 'seed-meta.json'
    meta.write_text(json.dumps({'schema_version': 1, 'source_url': SOURCE_URL, 'sha256': hashlib.sha256(data).hexdigest(),
                                'version': 1, 'checked_at': clock[0], 'downloaded_at': clock[0]}))
    calls = []
    responses = []
    def handler(request):
        calls.append(request)
        result = responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result
    store = MispGalaxyStore(tmp_path / 'runtime', seed, meta,
                           transport=httpx.MockTransport(handler), clock=lambda: clock[0])
    return store, clock, calls, responses


def test_merge_keeps_mitre_identity_and_adds_misp_only_names_without_mutation(mitre, galaxy):
    original = deepcopy(mitre)
    actors, guarded = merge_actors(mitre, galaxy)
    assert mitre == original
    assert actors[0]['name'] == 'APT28'
    assert 'Fighting Ursa' in actors[0]['aliases']
    assert 'Mapped Actor' in actors[0]['aliases']
    assert sum(actor['name'] == 'APT28' for actor in actors) == 1
    assert 'New Cyber Group' in {actor['name'] for actor in actors}
    assert {'A Campaign', 'An Operation'}.isdisjoint({actor['name'] for actor in actors})
    assert ('New Cyber Group', 'silence') in guarded


@pytest.mark.asyncio
async def test_detection_preserves_canonical_names_conflicts_context_and_boundaries(tmp_path, mitre, galaxy):
    catalog = tmp_path / 'actors.json'
    catalog.write_text(json.dumps({'actors': mitre}))
    enricher = ThreatActorEnricher(catalog, galaxy=galaxy)
    original = Article(title='Fighting Ursa and New Alias hacker groups', source='Source',
                       summary='Shared Alias. Silence in ordinary prose.', url='https://example.com')
    enriched = await enricher.enrich(original)
    assert enriched.threat_actors == ['APT28', 'New Cyber Group']
    assert original.threat_actors == []
    for text in ('Silence is golden.', 'Fighting Ursa2', 'APT280', 'https://example.com/Fighting Ursa', 'Fighting Ursa.test'):
        article = replace(original, title=text, summary='')
        assert (await enricher.enrich(article)).threat_actors == []
    contextual = await enricher.enrich(replace(original, title='The hacker group Silence attacked.', summary=''))
    assert contextual.threat_actors == ['New Cyber Group']
    assert await enricher.enrich(enriched) == enriched


def test_conflicting_crosswalks_do_not_merge_profiles(mitre, galaxy):
    galaxy['values'] = [cluster('Mixed Actor', ['G0007', 'G0016', 'Mixed Alias']),
                        cluster('APT28', ['G0016', 'Wrong Alias'])]
    actors, _ = merge_actors(mitre, galaxy)
    assert actors == [{'name': actor['name'], 'aliases': actor['aliases']} for actor in mitre]


def test_ref_crosswalk_requires_exact_official_mitre_host(mitre, galaxy):
    galaxy['values'] = [cluster('Mapped', ['Extra Alias'], refs=['https://attack.mitre.org/groups/G0007/'])]
    actors, _ = merge_actors(mitre, galaxy)
    assert 'Extra Alias' in actors[0]['aliases']
    galaxy['values'][0]['meta']['refs'] = ['https://attack.mitre.org.evil.test/groups/G0007/']
    actors, _ = merge_actors(mitre, galaxy)
    assert 'Extra Alias' not in actors[0]['aliases']
    assert actors[-1]['name'] == 'Mapped'


def test_shared_synonyms_never_pick_first_actor_and_mitre_names_cannot_be_claimed(mitre, galaxy):
    galaxy['values'] = [cluster('Broad Alias', ['Fancy Bear', 'Cozy Bear']),
                        cluster('Mapped', ['G0007', 'APT29', 'Extra Alias'])]
    actors, _ = merge_actors(mitre, galaxy)
    assert len(actors) == 2
    assert 'APT29' not in actors[0]['aliases']
    assert 'Extra Alias' in actors[0]['aliases']


def test_local_alias_removals_are_not_reintroduced(mitre, galaxy):
    overrides = {'schema_version': 1, 'actors': [{'attack_id': 'G0007', 'remove_aliases': ['Fighting Ursa']}]}
    actors, _ = merge_actors(mitre, galaxy, overrides)
    assert 'Fighting Ursa' not in actors[0]['aliases']


@pytest.mark.parametrize('mutate', [lambda g: g.update(type='malware'), lambda g: g.update(uuid=str(uuid4())),
                                    lambda g: g.update(version=True), lambda g: g.update(values=[]),
                                    lambda g: g['values'][0].update(uuid='bad'),
                                    lambda g: g['values'][0]['meta'].update(synonyms='bad'),
                                    lambda g: g['values'][0]['meta'].update(refs=1)])
def test_invalid_galaxy_is_rejected(galaxy, mutate):
    mutate(galaxy)
    with pytest.raises(ValueError):
        validate_galaxy(galaxy)


def test_seed_is_saved_locally_and_weekly_check_is_not_due(setup_store):
    store, clock, calls, responses = setup_store
    assert store.refresh() == 'fresh'
    assert store.file.read_bytes() == store.seed_file.read_bytes()
    assert calls == []
    assert store.status()['interval_hours'] == 168
    assert store.status()['next_check']
    clock[0] += 7 * 86400 - 1
    assert store.refresh() == 'fresh'
    assert calls == []


def test_weekly_update_and_conditional_304(setup_store, galaxy):
    store, clock, calls, responses = setup_store
    store.refresh()
    clock[0] += 7 * 86400
    galaxy['version'] = 2
    responses.append(httpx.Response(200, json=galaxy, headers={'ETag': '"v2"'}))
    assert store.refresh() == 'updated'
    assert store.load()['version'] == 2
    assert len(calls) == 1
    saved = store.file.read_bytes()
    clock[0] += 7 * 86400
    responses.append(httpx.Response(304))
    assert store.refresh() == 'not_modified'
    assert calls[-1].headers['if-none-match'] == '"v2"'
    assert store.file.read_bytes() == saved
    assert store.refresh() == 'fresh'
    assert len(calls) == 2


@pytest.mark.parametrize('failure', ['json', 'schema', 'size', 'timeout', 'http', 'redirect'])
def test_failed_update_preserves_valid_local_copy_and_retries_later(setup_store, galaxy, failure):
    store, clock, calls, responses = setup_store
    store.refresh()
    saved = store.file.read_bytes()
    clock[0] += 7 * 86400
    response = {'json': httpx.Response(200, content=b'bad'),
                'schema': httpx.Response(200, json={'type': 'malware'}),
                'size': httpx.Response(200, content=b'x' * (store.MAX_BYTES + 1)),
                'timeout': httpx.ReadTimeout('timeout'), 'http': httpx.Response(503),
                'redirect': httpx.Response(302, headers={'Location': 'http://127.0.0.1/'})}[failure]
    responses.append(response)
    assert store.refresh() == 'failed'
    assert store.file.read_bytes() == saved
    assert store.load()['version'] == 1
    assert store.status()['last_error']
    assert store.refresh() == 'backoff'
    assert len(calls) == 1
    clock[0] += store.RETRY_SECONDS
    responses.append(httpx.Response(200, json=galaxy))
    assert store.refresh() == 'updated'
    assert store.status()['last_error'] is None


def test_lock_prevents_parallel_updates(setup_store):
    store, clock, calls, responses = setup_store
    with store._lock() as acquired:
        assert acquired
        assert store.refresh(force=True) == 'busy'
    assert calls == []


def test_corrupt_runtime_falls_back_to_packaged_copy_and_recovers(setup_store, galaxy):
    store, clock, calls, responses = setup_store
    store.refresh()
    store.file.write_text('bad json')
    assert store.load()['version'] == 1
    responses.append(httpx.Response(200, json=galaxy))
    assert store.refresh() == 'updated'
    assert store.file.read_bytes() != b'bad json'
    assert 'if-none-match' not in calls[0].headers


@pytest.mark.parametrize('interval', [0, -1, float('nan'), float('inf')])
def test_invalid_update_period_is_rejected(setup_store, interval):
    store, *_ = setup_store
    with pytest.raises(ValueError):
        MispGalaxyStore(store.directory, store.seed_file, store.seed_metadata, interval_hours=interval)


@pytest.mark.asyncio
async def test_collection_reloads_weekly_galaxy_without_restarting_container(tmp_path, setup_store, galaxy):
    import feedparser
    from unittest.mock import AsyncMock
    from app.container import ApplicationContainer
    from config.models import Feed
    from feeds.models import FeedResult
    from storage.sqlite_storage import SQLiteArticleRepository
    from storage.backup import create_backup, restore_backup

    store, clock, calls, responses = setup_store
    feeds = tmp_path / 'feeds'
    feeds.mkdir()
    (feeds / 'news.yaml').write_text('category: news\nfeeds:\n  - name: Source\n    url: https://example.com/rss\n')
    container = ApplicationContainer(database_file=tmp_path / 'archive.sqlite3', config_directory=feeds,
                                     misp_auto_update=True)
    container.misp_store = store
    def feed(text):
        parsed = feedparser.parse(f'<rss version="2.0"><channel><title>Source</title><item><title>{text}</title>'
                                 '<link>https://example.com/report</link></item></channel></rss>')
        return [FeedResult(feed=Feed(name='Source', url='https://example.com/rss', category='news'), parsed=parsed)]
    container.fetcher.fetch_all = AsyncMock(return_value=feed('New Alias group and Fighting Ursa'))
    await container.article_service.update(force_refresh=True)
    saved = container.repository.load()[0]
    assert saved.threat_actors == ['New Cyber Group', 'APT28']
    assert 'G0007' in saved.attack.entity_ids
    assert calls == []
    clock[0] += 7 * 86400
    galaxy['version'] = 2
    galaxy['values'].append(cluster('Weekly Added Group', ['Weekly Alias']))
    responses.append(httpx.Response(200, json=galaxy))
    container.fetcher.fetch_all.return_value = feed('Weekly Alias group')
    await container.article_service.update(force_refresh=True)
    updated = container.repository.load()[0]
    assert updated.threat_actors == ['Weekly Added Group']
    assert updated.attack.entity_ids == []  # MISP-only identity does not invent MITRE relationships.
    assert len(calls) == 1
    snapshot = create_backup(container.repository.database_file, tmp_path / 'backups')
    restored = restore_backup(snapshot, tmp_path / 'restored.sqlite3')
    assert SQLiteArticleRepository(restored).load()[0] == updated
    # Automatic refresh can be disabled, while a manually changed local file is still reloaded.
    container.misp_auto_update = False
    payload = deepcopy(galaxy)
    payload['values'].append(cluster('Offline Added Group', ['Offline Alias']))
    store.file.write_text(json.dumps(payload))
    container.fetcher.fetch_all.return_value = feed('Offline Alias group')
    await container.article_service.update(force_refresh=True)
    assert container.repository.load()[0].threat_actors == ['Offline Added Group']
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_callback_failure_and_catalog_http_failure_do_not_stop_feed_collection(tmp_path, setup_store):
    import feedparser
    from unittest.mock import AsyncMock
    from app.container import ApplicationContainer
    from config.models import Feed
    from feeds.models import FeedResult

    store, clock, calls, responses = setup_store
    feeds = tmp_path / 'feeds'
    feeds.mkdir()
    (feeds / 'news.yaml').write_text('category: news\nfeeds:\n  - name: Source\n    url: https://example.com/rss\n')
    container = ApplicationContainer(database_file=tmp_path / 'archive.sqlite3', config_directory=feeds,
                                     misp_auto_update=True)
    container.misp_store = store
    store.refresh()
    clock[0] += 7 * 86400
    responses.append(httpx.Response(503))
    parsed = feedparser.parse('<rss version="2.0"><channel><title>Source</title><item><title>New Alias group</title>'
                             '<link>https://example.com/report</link></item></channel></rss>')
    container.fetcher.fetch_all = AsyncMock(return_value=[FeedResult(
        feed=Feed(name='Source', url='https://example.com/rss', category='news'), parsed=parsed)])
    assert (await container.article_service.update(force_refresh=True)).articles_saved == 1
    assert container.repository.load()[0].threat_actors == ['New Cyber Group']
    container.article_service._before_collection = AsyncMock(side_effect=ValueError('bad configuration'))
    assert (await container.article_service.update(force_refresh=True)).articles_saved == 1
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_valid_article_cache_does_not_trigger_catalog_http(tmp_path, setup_store):
    from unittest.mock import AsyncMock
    from app.container import ApplicationContainer

    store, clock, calls, responses = setup_store
    feeds = tmp_path / 'feeds'
    feeds.mkdir()
    container = ApplicationContainer(database_file=tmp_path / 'archive.sqlite3', config_directory=feeds,
                                     misp_auto_update=True)
    container.misp_store = store
    container.repository.refresh([Article(title='Cached report', source='Source', summary='', url='https://example.com')])
    container.fetcher.fetch_all = AsyncMock(side_effect=AssertionError('Cache should be reused'))
    result = await container.article_service.update()
    assert result.cache_used
    assert calls == []


def test_cli_status_and_interval_validation_without_network(tmp_path, setup_store, monkeypatch, capsys):
    from tools import update_misp_galaxy
    store, clock, calls, responses = setup_store
    monkeypatch.setattr(update_misp_galaxy, 'MispGalaxyStore', lambda *args, **kwargs: store)
    monkeypatch.setattr('sys.argv', ['rss-update-misp', '--status'])
    update_misp_galaxy.main()
    assert json.loads(capsys.readouterr().out)['interval_hours'] == 168
    assert calls == []
    monkeypatch.setattr('sys.argv', ['rss-update-misp', '--force', '--status'])
    with pytest.raises(SystemExit) as exc:
        update_misp_galaxy.main()
    assert exc.value.code == 2


@pytest.mark.asyncio
async def test_generic_aliases_and_group_number_do_not_supply_their_own_context(tmp_path, mitre, galaxy):
    galaxy['values'] = [cluster('Actual Cyber Group', ['Unknown', 'Group 3'])]
    catalog = tmp_path / 'actors.json'
    catalog.write_text(json.dumps({'actors': mitre}))
    enricher = ThreatActorEnricher(catalog, galaxy=galaxy)
    for text in ('Unknown attackers breached a target.', 'Group 3 benchmark results.'):
        result = await enricher.enrich(Article(title=text, summary='', source='Source', url='https://example.com'))
        assert result.threat_actors == []
    result = await enricher.enrich(Article(title='Attacker Group 3 breached a target.', summary='', source='Source', url='https://example.com'))
    assert result.threat_actors == ['Actual Cyber Group']


@pytest.mark.asyncio
async def test_conflicting_misp_import_does_not_remove_existing_mitre_alias(tmp_path, mitre, galaxy):
    galaxy['values'] = [cluster('Mapped To APT29', ['G0016', 'Fancy Bear', 'Extra Alias'])]
    catalog = tmp_path / 'actors.json'
    catalog.write_text(json.dumps({'actors': mitre}))
    enricher = ThreatActorEnricher(catalog, galaxy=galaxy)
    result = await enricher.enrich(Article(title='Fancy Bear and Extra Alias', summary='', source='Source', url='https://example.com'))
    assert result.threat_actors == ['APT28', 'APT29']
