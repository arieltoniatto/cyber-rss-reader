from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import json
import logging

import pytest

from alerts.config import AlertSettings, Destination, Rules
from alerts.outbox import AlertOutbox
from alerts.service import AlertService, send
from parser.models import Article, IOC, IOCType
from storage.sqlite_storage import SQLiteArticleRepository


def article(name='Report'):
    return Article(title=name, source='Research', summary='Evidence', category='news',
                   url=f'https://example.com/{name}', tags=['research'], threat_actors=['APT28'],
                   iocs=[IOC(IOCType.CVE, 'CVE-2026-1234')])


@pytest.fixture
def configured(tmp_path):
    repo = SQLiteArticleRepository(tmp_path/'archive.sqlite3')
    repo.alert_settings = AlertSettings(destinations=[Destination(id='soc', url_env='SOC_URL')])
    return repo


def test_queue_only_new_matches_deduplicates_and_is_transactional(configured):
    repo = configured
    repo.alert_settings.destinations[0].rules = Rules(threat_actors=['apt28'], ioc_types=[IOCType.CVE])
    repo.save([article('Existing')])
    repo.save_collection([article(), article(), article('Existing'), replace(article('Other'), threat_actors=[])], [])
    outbox = AlertOutbox(repo)
    assert outbox.status()['pending'] == 1
    repo.save_collection([replace(article(), title='Updated')], [])
    assert outbox.status()['pending'] == 1
    with pytest.raises(AttributeError):
        repo.save_collection([article('Rolled-back'), replace(article('Bad'), tags=[None])], [])
    assert outbox.status()['pending'] == 1
    assert len(repo.load()) == 3


def test_disabled_and_save_import_do_not_alert(tmp_path):
    repo = SQLiteArticleRepository(tmp_path/'archive.sqlite3')
    repo.save_collection([article()], [])
    assert AlertOutbox(repo).status()['pending'] == 0
    repo.alert_settings = AlertSettings(destinations=[Destination(id='soc', url_env='SOC_URL')])
    repo.save([article('Import')])
    repo.refresh([article('Refresh')])
    assert AlertOutbox(repo).status()['pending'] == 0


def test_delivery_receipt_survives_restart_and_retention(configured):
    repo = configured
    repo.save_collection([article()], [])
    calls = []
    service = AlertService(repo, repo.alert_settings, sender=lambda *args: calls.append(args))
    assert service.dispatch() == {'sent': 1, 'failed': 0}
    restarted = AlertService(SQLiteArticleRepository(repo.database_file), repo.alert_settings, sender=lambda *args: calls.append(args))
    assert restarted.dispatch()['sent'] == 0
    with repo._connection() as connection:
        connection.execute('DELETE FROM articles')
    repo.save_collection([article()], [])
    assert service.dispatch()['sent'] == 0
    assert len(calls) == 1
    assert 'article' not in json.dumps(restarted.outbox.claim(repo.alert_settings))


def test_leases_concurrency_retry_backoff_and_terminal_failure(configured):
    repo = configured
    repo.save_collection([article()], [])
    outbox = AlertOutbox(repo)
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(lambda _: outbox.claim(repo.alert_settings, now=1000), range(2)))
    assert sum(result is not None for result in claims) == 1
    key, state = next(result for result in claims if result)
    assert outbox.claim(repo.alert_settings, now=1100) is None
    # A crashed sender's lease expires, allowing another process to recover.
    key2, recovered = outbox.claim(repo.alert_settings, now=1121)
    assert key2 == key and recovered['attempts'] == 2
    outbox.finish(key, state, now=1122)  # Stale acknowledgement must not win.
    assert outbox.status()['sending'] == 1
    outbox.finish(key, recovered, error='HTTP 503', now=1122)
    assert outbox.claim(repo.alert_settings, now=1241) is None
    key3, last = outbox.claim(repo.alert_settings, now=1243)
    outbox.finish(key3, last, error='HTTP 503', now=1243)
    assert outbox.status()['failed'] == 1
    assert outbox.retry_failed() == 1
    assert outbox.claim(repo.alert_settings, now=1244)[1]['attempts'] == 1


def test_paused_destination_keeps_queued_items(configured):
    configured.save_collection([article()], [])
    settings = configured.alert_settings
    settings.destinations[0].enabled = False
    assert AlertOutbox(configured).claim(settings) is None
    assert AlertOutbox(configured).status()['pending'] == 1


def test_config_validates_before_opening_archive(tmp_path, monkeypatch):
    from storage.factory import create_repository
    config = tmp_path/'alerts.json'
    config.write_text(json.dumps({'destinations': [{'id': 'soc', 'url_env': 'MISSING_URL'}]}))
    monkeypatch.setenv('CYBER_RSS_ALERT_CONFIG', str(config))
    with pytest.raises(ValueError, match='Missing or invalid environment variable'):
        create_repository(database_file=tmp_path/'not-created.sqlite3')
    assert not (tmp_path/'not-created.sqlite3').exists()
    config.write_text('{"unexpected_secret": "do-not-log"}')
    with pytest.raises(ValueError) as error:
        AlertSettings.from_environment()
    assert 'do-not-log' not in str(error.value)


def test_generic_payload_and_telegram_plaintext_do_not_expose_credentials(monkeypatch, caplog):
    monkeypatch.setenv('BOT_TOKEN', '123456:do-not-log')
    monkeypatch.setenv('CHAT_ID', '-1001234567')
    monkeypatch.setenv('SOC_URL', 'https://example.com/secret-path')
    monkeypatch.setenv('SOC_TOKEN', 'do-not-log')
    captured = []
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return b'{"ok":true}'
    class Opener:
        def open(self, request, timeout):
            captured.append(request)
            return Response()
    monkeypatch.setattr('alerts.service.build_opener', lambda *args: Opener())
    event = {'id': 'stable-event-id', 'article': {'title': '<b>Report</b>', 'source': 'Source',
                                               'url': 'https://example.com/report', 'summary': 'Evidence'}}
    caplog.set_level(logging.DEBUG)
    assert send(Destination(id='telegram', kind='telegram', token_env='BOT_TOKEN', chat_id_env='CHAT_ID'), event, 5) is None
    payload = json.loads(captured[-1].data)
    assert payload['chat_id'] == '-1001234567'
    assert '<b>Report</b>' in payload['text']
    assert 'parse_mode' not in payload and payload['link_preview_options']['is_disabled']
    assert send(Destination(id='soc', url_env='SOC_URL', token_env='SOC_TOKEN'), event, 5) is None
    assert json.loads(captured[-1].data) == event
    assert captured[-1].get_header('Idempotency-key') == event['id']
    assert captured[-1].get_header('Authorization') == 'Bearer do-not-log'
    assert 'do-not-log' not in caplog.text and 'secret-path' not in caplog.text


def test_sender_failure_is_queued_without_secrets(configured):
    configured.save_collection([article()], [])
    def fail(*args):
        raise RuntimeError('sensitive-url-and-token')
    service = AlertService(configured, configured.alert_settings, sender=fail)
    assert service.dispatch()['failed'] == 1
    assert service.outbox.status()['pending'] == 1
    assert 'sensitive' not in json.dumps(service.outbox.status())


def test_http_failures_and_telegram_rejections_are_sanitized(monkeypatch):
    from urllib.error import HTTPError
    from alerts.service import NoRedirect
    monkeypatch.setenv('SOC_URL', 'https://example.com/private-secret')
    class Failure:
        def open(self, *args, **kwargs):
            raise HTTPError('https://example.com/private-secret', 429, 'sensitive response', {}, None)
    monkeypatch.setattr('alerts.service.build_opener', lambda *args: Failure())
    assert send(Destination(id='soc', url_env='SOC_URL'), {'id': 'event'}, 5) == 'HTTP 429'
    assert NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.example') is None
    monkeypatch.setenv('BOT_TOKEN', '1234:private-secret')
    monkeypatch.setenv('CHAT_ID', '1234')
    class Rejected:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return b'{"ok":false,"description":"sensitive response"}'
    class Opener:
        def open(self, *args, **kwargs): return Rejected()
    monkeypatch.setattr('alerts.service.build_opener', lambda *args: Opener())
    event = {'id': 'event', 'article': {'title': 'Report', 'source': 'Source', 'url': '', 'summary': ''}}
    destination = Destination(id='telegram', kind='telegram', token_env='BOT_TOKEN', chat_id_env='CHAT_ID')
    assert send(destination, event, 5) == 'Telegram rejected the message'
