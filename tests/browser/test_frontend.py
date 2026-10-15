"""Browser tests: install .[dev,browser], then playwright install chromium."""
from datetime import datetime, timezone
from dataclasses import replace
import os
import re
import socket
import subprocess
import sys
import time

import httpx
import pytest

pytest.importorskip('playwright.sync_api')
from playwright.sync_api import sync_playwright, expect

from config.models import Feed
from feeds.models import FeedObservation
from parser.models import Article, IOC, IOCType
from storage.sqlite_storage import SQLiteArticleRepository


@pytest.fixture(scope='module')
def frontend_server(tmp_path_factory):
    directory = tmp_path_factory.mktemp('frontend')
    database = directory / 'archive.sqlite3'
    repo = SQLiteArticleRepository(database)
    articles = [Article(title=f'Malware report {i:02}', source='Source A' if i % 2 == 0 else 'Source B',
                        category='news' if i % 2 == 0 else 'malware',
                        summary=f'Investigation of ransomware campaign {i}.' + (' T1059.001 C0001' if i == 24 else ''), url=f'https://example.com/{i}',
                        tags=['ransomware' if i % 2 == 0 else 'research'], malware=['BlackEnergy'],
                        threat_actors=['APT28'], iocs=[IOC(IOCType.CVE, 'CVE-2026-1234')],
                        published=datetime(2026, 1, i + 1, tzinfo=timezone.utc)) for i in range(26)]
    # Exercise RSS parsing, persistence, API serialization and the detail view.
    import feedparser
    from feeds.models import FeedResult
    from parser.parser import RSSParser
    body = articles[24].summary + ' Extended research evidence.' * 80 + ' End of extended feed content.'
    xml = f'<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><title>Research</title><item><title>Report</title><description>Short preview.</description><content:encoded><![CDATA[<p>{body}</p>]]></content:encoded></item></channel></rss>'
    parsed = RSSParser().parse([FeedResult(feed=Feed(name='Source A', url='https://example.com/feed'), parsed=feedparser.parse(xml.encode()))])[0]
    articles[24] = replace(articles[24], summary=parsed.summary)
    articles.append(Article(title='<img src=x onerror="window.__xss=1">', source='Source A',
                            category='news', summary='<script>window.__xss=1</script>',
                            url='javascript:window.__xss=1', tags=['ransomware'],
                            malware=['BlackEnergy'], threat_actors=['APT28'],
                            iocs=[IOC(IOCType.URL, '<svg onload="window.__xss=1">')],
                            published=datetime(2026, 2, 1, tzinfo=timezone.utc)))
    now = datetime.now(timezone.utc)
    repo.save_collection(articles, [
        FeedObservation(feed=Feed(name='Source A', url='https://example.com/a'),
                        attempted_at=now, completed_at=now, article_count=14),
        FeedObservation(feed=Feed(name='Source B', url='https://example.com/b'),
                        attempted_at=now, completed_at=now, error='HTTP 404'),
    ])
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    with (directory / 'server.log').open('w') as log:
        # These functional tests intentionally navigate faster than human users.
        # Authentication and request budgets are covered separately.
        environment = {key: value for key, value in os.environ.items()
                       if key not in ('CYBER_RSS_AUTH_FILE', 'CYBER_RSS_TLS_CERT_FILE', 'CYBER_RSS_TLS_KEY_FILE')}
        environment['CYBER_RSS_BACKUP_DIR'] = str(directory / 'backups')
        environment.update({name: '10000' for name in ('CYBER_RSS_RATE_PER_MINUTE', 'CYBER_RSS_RATE_BURST',
                                                       'CYBER_RSS_RATE_GLOBAL_PER_MINUTE', 'CYBER_RSS_RATE_GLOBAL_BURST')})
        process = subprocess.Popen([sys.executable, '-m', 'web_api.app', '--database', str(database),
                                    '--port', str(port)], stdout=log, stderr=subprocess.STDOUT, env=environment)
        base_url = f'http://127.0.0.1:{port}'
        try:
            for _ in range(120):
                if process.poll() is not None:
                    raise RuntimeError((directory / 'server.log').read_text())
                try:
                    if httpx.get(base_url + '/health', timeout=1, trust_env=False).status_code == 200:
                        break
                except httpx.ConnectError:
                    pass
                time.sleep(0.1)
            else:
                raise RuntimeError('Server did not start')
            yield base_url
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


@pytest.fixture
def page(frontend_server):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(viewport={'width': 1440, 'height': 1000})
        page = context.new_page()
        page.goto(frontend_server)
        expect(page.locator('#stat-articles')).to_have_text('27')
        expect(page.locator('#article-list')).to_have_attribute('aria-busy', 'false')
        yield page
        context.close()
        browser.close()


def test_pagination_search_filters_and_reload(page):
    expect(page.locator('.article-card')).to_have_count(20)
    page.locator('#next').click()
    expect(page.locator('#page-number')).to_have_text('Página 2')
    expect(page.locator('.article-card')).to_have_count(7)
    page.locator('#previous').click()
    expect(page.locator('#page-number')).to_have_text('Página 1')
    page.get_by_label('Buscar artigos', exact=True).fill('malware')
    page.get_by_role('button', name='Buscar', exact=False).click()
    expect(page.locator('#results-title')).to_have_text('Resultados para “malware”')
    page.locator('#source').select_option('Source A')
    page.locator('#tag').fill('ransomware')
    page.locator('#tag').press('Enter')
    expect(page.locator('#article-list')).to_have_attribute('aria-busy', 'false')
    expect(page.locator('.article-card')).to_have_count(14)
    page.reload()
    expect(page.locator('#search')).to_have_value('malware')
    expect(page.locator('#source')).to_have_value('Source A')
    expect(page.locator('#tag')).to_have_value('ransomware')
    expect(page.locator('.article-card')).to_have_count(14)
    page.get_by_role('button', name='Limpar filtros').click()
    expect(page.locator('.article-card')).to_have_count(20)


def test_details_escape_deep_link_and_untrusted_text(page):
    first = page.locator('.article-title').first
    first.click()
    expect(page.locator('#article-dialog')).to_be_visible()
    expect(page.locator('#detail-title')).to_contain_text('<img')
    expect(page.locator('.detail-summary')).to_contain_text('<script>')
    expect(page.locator('#article-dialog img, #article-dialog script, #article-dialog svg')).to_have_count(0)
    assert page.evaluate('window.__xss') is None
    expect(page.get_by_role('link', name='Abrir artigo original')).to_have_count(0)
    expect(page.locator('.ioc-value')).to_contain_text('<svg')
    page.keyboard.press('Escape')
    expect(page.locator('#article-dialog')).not_to_be_visible()
    expect(first).to_be_focused()
    page.get_by_role('button', name='Malware report 24', exact=True).click()
    expect(page.get_by_role('link', name='Abrir artigo original')).to_have_attribute('href', 'https://example.com/24')
    expect(page.locator('#detail-content')).to_contain_text('BlackEnergy')
    expect(page.locator('#detail-content')).to_contain_text('APT28')
    page.reload()
    expect(page.locator('#detail-title')).to_have_text('Malware report 24')
    expect(page.locator('#article-dialog')).to_be_visible()


def test_mobile_navigation_and_layout(page):
    page.set_viewport_size({'width': 390, 'height': 844})
    expect(page.locator('#sidebar')).to_have_attribute('inert', '')
    page.get_by_role('button', name='Abrir navegação').click()
    page.locator('#categories').get_by_role('button', name='Notícias').click()
    expect(page.locator('#results-title')).to_have_text('Notícias')
    expect(page.locator('.article-card')).to_have_count(14)
    expect(page.locator('#menu-toggle')).to_have_attribute('aria-expanded', 'false')
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    page.locator('.article-title').first.click()
    expect(page.locator('#article-dialog')).to_be_visible()
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')


def test_feed_errors_and_empty_search(page):
    page.locator('#stat-errors-button').click()
    expect(page.locator('#feed-filter')).to_have_value('error')
    expect(page.locator('.feed-card')).to_have_count(1)
    expect(page.locator('.feed-error')).to_have_text('HTTP 404')
    expect(page.locator('.feed-card')).to_contain_text('Sem sucesso registrado')
    page.locator('#nav-articles').click()
    page.locator('#tag').fill('unknown-tag-that-does-not-exist')
    page.locator('#tag').press('Enter')
    expect(page.locator('#articles-message')).to_contain_text('Nenhum artigo encontrado')
    expect(page.locator('.article-card')).to_have_count(0)


def test_failed_request_can_be_retried(page):
    page.route('**/articles?*', lambda route: route.fulfill(status=503, body='Unavailable'))
    page.locator('#refresh').click()
    expect(page.locator('#articles-message')).to_contain_text('Não foi possível carregar os artigos')
    page.unroute('**/articles?*')
    page.get_by_role('button', name='Tentar novamente').click()
    expect(page.locator('.article-card')).to_have_count(20)


def test_browser_back_restores_category(page):
    page.locator('#categories').get_by_role('button', name='Notícias').click()
    expect(page.locator('#results-title')).to_have_text('Notícias')
    page.locator('#categories').get_by_role('button', name='Malware').click()
    expect(page.locator('#results-title')).to_have_text('Malware')
    page.go_back()
    expect(page.locator('#results-title')).to_have_text('Notícias')
    expect(page.locator('.article-card')).to_have_count(14)


@pytest.mark.parametrize('outcome', ['completed', 'cached', 'failed'])
def test_manual_collection_controls_and_result(page, outcome):
    running = False
    checks = 0
    requests = []
    def collection(route):
        nonlocal running, checks
        if route.request.method == 'POST':
            requests.append(route.request.post_data_json)
            assert route.request.headers['x-cyber-rss-request'] == '1'
            running = True
            route.fulfill(status=202, json={'status': 'running'})
        elif not running:
            route.fulfill(json={'status': 'idle'})
        else:
            checks += 1
            if checks == 1:
                route.fulfill(json={'status': 'running', 'source': 'manual'})
            elif outcome == 'failed':
                route.fulfill(json={'status': 'failed', 'error': 'A coleta falhou. Tente novamente.'})
            else:
                route.fulfill(json={'status': 'completed', 'result': {
                    'feeds_downloaded': 2, 'feeds_failed': 1, 'articles_saved': 6,
                    'cache_used': outcome == 'cached'}})
    page.route('**/collection', collection)
    page.locator('#refresh').click()
    expect(page.locator('#collect-now')).to_be_enabled()
    if outcome == 'cached':
        page.locator('#force-refresh').uncheck()
    page.locator('#collect-now').click()
    expect(page.locator('#collect-now')).to_be_disabled()
    expect(page.locator('#collection-status')).to_contain_text('Baixando e processando')
    expect(page.locator('#collect-now')).to_be_enabled(timeout=10000)
    assert requests == [{'force_refresh': outcome != 'cached'}]
    expected = {'completed': '2 feeds baixados, 1 com erro e 6 artigos salvos ou atualizados',
                'cached': 'O arquivo ainda está atualizado', 'failed': 'A coleta falhou'}
    expect(page.locator('#collection-status')).to_contain_text(expected[outcome])
    expect(page.locator('.article-card')).to_have_count(20)


def test_topics_limits_reload_history_and_search(page, frontend_server):
    page.goto(frontend_server + '/?view=topics&topicLimit=10&category=news&source=Source+B&tag=missing')
    expect(page.locator('#topic-list')).to_have_attribute('aria-busy', 'false')
    expect(page.locator('.topic-card')).to_have_count(10)
    expect(page.locator('#topics-limit')).to_have_value('10')
    expect(page.locator('#nav-topics')).to_have_attribute('aria-current', 'page')
    expect(page.locator('#articles-section')).not_to_be_visible()
    with page.expect_response(lambda response: '/topics?limit=50' in response.url):
        page.locator('#topics-limit').select_option('50')
    expect(page.locator('#topic-list')).to_have_attribute('aria-busy', 'false')
    assert 10 < page.locator('.topic-card').count() <= 50
    page.reload()
    expect(page.locator('#topics-limit')).to_have_value('50')
    expect(page.locator('#topic-list')).to_have_attribute('aria-busy', 'false')
    term = page.locator('.topic-term').first.inner_text()
    page.locator('.topic-card').first.click()
    expect(page.locator('#search')).to_have_value(term)
    expect(page.locator('#source')).to_have_value('')
    expect(page.locator('#tag')).to_have_value('')
    expect(page.locator('#active-category')).not_to_be_visible()
    expect(page.locator('#nav-articles')).to_have_attribute('aria-current', 'page')
    expect(page.locator('#article-list')).to_have_attribute('aria-busy', 'false')
    assert page.locator('.article-card').count() > 0
    page.go_back()
    expect(page.locator('#topics-section')).to_be_visible()
    expect(page.locator('#topics-limit')).to_have_value('50')


def test_topics_empty_failure_retry_and_untrusted_text(page):
    page.route('**/topics?*', lambda route: route.fulfill(status=503, body='Unavailable'))
    page.locator('#nav-topics').click()
    expect(page.locator('#topics-message')).to_contain_text('Não foi possível carregar os tópicos')
    page.unroute('**/topics?*')
    page.route('**/topics?*', lambda route: route.fulfill(json={'items': []}))
    page.locator('#topics-message').get_by_role('button', name='Tentar novamente').click()
    expect(page.locator('#topics-message')).to_contain_text('Nenhum tópico disponível')
    expect(page.locator('.topic-card')).to_have_count(0)
    page.unroute('**/topics?*')
    page.route('**/topics?*', lambda route: route.fulfill(json={'items': [
        {'topic': '<img src=x onerror="window.__topic_xss=1">', 'score': 1.2, 'frequency': 3}]}))
    page.locator('#refresh').click()
    expect(page.locator('.topic-card')).to_have_count(1)
    expect(page.locator('.topic-term')).to_contain_text('<img')
    expect(page.locator('#topic-list img, #topic-list script')).to_have_count(0)
    assert page.evaluate('window.__topic_xss') is None


def test_topics_mobile_layout_and_invalid_limit(page, frontend_server):
    page.set_viewport_size({'width': 390, 'height': 844})
    page.goto(frontend_server + '/?view=topics&topicLimit=-1')
    expect(page.locator('#topics-limit')).to_have_value('20')
    expect(page.locator('#topic-list')).to_have_attribute('aria-busy', 'false')
    page.wait_for_timeout(250)  # Finish the responsive sidebar transition.
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    page.get_by_role('button', name='Abrir navegação').click()
    page.locator('#nav-articles').click()
    page.get_by_role('button', name='Abrir navegação').click()
    page.locator('#nav-topics').click()
    expect(page.locator('#menu-toggle')).to_have_attribute('aria-expanded', 'false')
    expect(page.locator('#topic-list')).to_have_attribute('aria-busy', 'false')
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    page.screenshot(path='logs/topics-mobile.png')


def test_topics_refresh_after_collection_finishes(page):
    running = False
    checks = 0
    topic_requests = []
    def topics(route):
        topic_requests.append(route.request.url)
        route.fulfill(json={'items': [{'topic': 'new topic' if checks > 1 else 'old topic',
                                      'score': 2.0, 'frequency': 1}]})
    def collection(route):
        nonlocal running, checks
        if route.request.method == 'POST':
            running = True
            route.fulfill(status=202, json={'status': 'running'})
        elif running:
            checks += 1
            route.fulfill(json={'status': 'running', 'source': 'manual'} if checks == 1 else {
                'status': 'completed', 'result': {'cache_used': False, 'feeds_downloaded': 1,
                                               'feeds_failed': 0, 'articles_saved': 1}})
        else:
            route.fulfill(json={'status': 'idle'})
    page.route('**/topics?*', topics)
    page.route('**/collection', collection)
    page.locator('#nav-topics').click()
    expect(page.locator('.topic-term')).to_have_text('old topic')
    page.locator('#refresh').click()
    expect(page.locator('#collect-now')).to_be_enabled()
    page.locator('#collect-now').click()
    expect(page.locator('.topic-term')).to_have_text('new topic', timeout=10000)
    assert len(topic_requests) >= 2


def test_manage_feeds_add_edit_toggle_and_reload(page):
    page.locator('#nav-sources').click()
    expect(page.locator('#source-list')).to_have_attribute('aria-busy', 'false')
    expect(page.locator('#nav-sources')).to_have_attribute('aria-current', 'page')
    page.locator('#add-feed').click()
    expect(page.locator('#feed-dialog')).to_be_visible()
    page.locator('#feed-name').fill('Fonte pessoal de teste')
    page.locator('#feed-url').fill('https://example.com/personal-feed')
    page.locator('#feed-category').fill('threat_hunting')
    page.locator('#feed-description').fill('Descrição pessoal')
    page.locator('#save-feed').click()
    expect(page.locator('#feed-dialog')).not_to_be_visible()
    card = page.locator('#source-list .feed-card').filter(has=page.get_by_role('heading', name='Fonte pessoal de teste', exact=True))
    expect(card).to_contain_text('Descrição pessoal')
    card.get_by_role('button', name='Desativar', exact=True).click()
    expect(card).to_contain_text('Desativado')
    page.locator('#sources-filter').select_option('disabled')
    expect(card).to_be_visible()
    card.get_by_role('button', name='Editar', exact=True).click()
    page.locator('#feed-url').fill('https://example.com/updated-feed')
    page.locator('#save-feed').click()
    expect(card).to_contain_text('https://example.com/updated-feed')
    page.reload()
    expect(card).to_contain_text('Desativado')
    expect(card).to_contain_text('https://example.com/updated-feed')
    card.get_by_role('button', name='Ativar', exact=True).click()
    expect(card).to_contain_text('Ativado')
    expect(page.locator('#stat-articles')).to_have_text('27')
    page.set_viewport_size({'width': 390, 'height': 844})
    page.wait_for_timeout(250)
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')


def test_manage_feeds_reports_duplicates_and_loading_failure(page):
    page.route('**/feed-config', lambda route: route.fulfill(status=503, body='Unavailable'))
    page.locator('#nav-sources').click()
    expect(page.locator('#sources-message')).to_contain_text('Não foi possível carregar a configuração')
    page.unroute('**/feed-config')
    page.locator('#sources-message').get_by_role('button', name='Tentar novamente').click()
    expect(page.locator('#source-list')).to_have_attribute('aria-busy', 'false')
    name = page.locator('#source-list h3').first.inner_text()
    page.locator('#add-feed').click()
    page.locator('#feed-name').fill(name)
    page.locator('#feed-url').fill('https://example.com/duplicate-test')
    page.locator('#save-feed').click()
    expect(page.locator('#feed-form-error')).to_contain_text('Já existe um feed')
    expect(page.locator('#feed-dialog')).to_be_visible()
    page.keyboard.press('Escape')
    expect(page.locator('#feed-dialog')).not_to_be_visible()


def test_feed_actions_disabled_during_collection(page):
    page.route('**/collection', lambda route: route.fulfill(json={'status': 'running', 'source': 'worker'}))
    page.locator('#nav-sources').click()
    page.locator('#refresh').click()
    expect(page.locator('#collection-status')).to_contain_text('coletor automático')
    expect(page.locator('#add-feed')).to_be_disabled()
    expect(page.locator('#source-list .feed-manage-action').first).to_be_disabled()


def test_backups_create_download_and_reload(page):
    page.locator('#nav-backups').click()
    expect(page.locator('#backups-section')).to_be_visible()
    expect(page.locator('#backups-message')).to_contain_text('Nenhum backup disponível')
    expect(page.locator('#create-backup')).to_be_enabled()
    page.locator('#create-backup').click()
    expect(page.locator('#backup-status')).to_contain_text('Backup concluído', timeout=10000)
    expect(page.locator('.backup-card')).to_have_count(1)
    expect(page.locator('.backup-card')).to_contain_text('27')
    with page.expect_download() as download_info:
        page.get_by_role('button', name='Baixar ZIP', exact=False).click()
    download = download_info.value
    assert download.suggested_filename.endswith('.zip')
    from zipfile import ZipFile
    with ZipFile(download.path()) as bundle:
        assert any(name.endswith('.sqlite3') for name in bundle.namelist())
        assert any(name.endswith('.json') for name in bundle.namelist())
    page.reload()
    expect(page.locator('.backup-card')).to_have_count(1)
    expect(page.locator('#nav-backups')).to_have_attribute('aria-current', 'page')
    page.set_viewport_size({'width': 390, 'height': 844})
    page.wait_for_timeout(250)
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')


def test_backups_loading_failure_retry_and_download_error(page):
    page.route('**/backups', lambda route: route.fulfill(status=503, body='Unavailable'))
    page.locator('#nav-backups').click()
    expect(page.locator('#backups-message')).to_contain_text('Não foi possível carregar os backups')
    page.unroute('**/backups')
    page.route('**/backups', lambda route: route.fulfill(json={'retention': 14, 'items': [
        {'id': 'articles-20261010T100000000000Z-1234abcd.sqlite3', 'created_at': '2026-10-10T10:00:00+00:00',
         'articles': 27, 'feeds': 2, 'size_bytes': 4096, 'downloadable': True}]}))
    page.locator('#backups-message').get_by_role('button', name='Tentar novamente').click()
    expect(page.locator('.backup-card')).to_have_count(1)
    page.route('**/backups/*/download', lambda route: route.fulfill(status=409, json={'detail': 'Backup danificado. Escolha outra cópia.'}))
    page.get_by_role('button', name='Baixar ZIP', exact=False).click()
    expect(page.locator('#backups-notice')).to_contain_text('Backup danificado')
    expect(page.get_by_role('button', name='Baixar ZIP', exact=False)).to_be_enabled()


def test_backup_running_and_failure_feedback(page):
    running = False
    checks = 0
    def status(route):
        nonlocal checks
        if not running:
            route.fulfill(json={'status': 'idle'})
        else:
            checks += 1
            route.fulfill(json={'status': 'running'} if checks == 1 else {
                'status': 'failed', 'error': 'Não foi possível gerar o backup. Tente novamente.'})
    def start(route):
        nonlocal running
        running = True
        assert route.request.headers['x-cyber-rss-request'] == '1'
        route.fulfill(status=202, json={'status': 'running'})
    page.route('**/backups/status', status)
    page.route('**/backups', lambda route: start(route) if route.request.method == 'POST' else route.continue_())
    page.locator('#nav-backups').click()
    expect(page.locator('#create-backup')).to_be_enabled()
    page.locator('#create-backup').click()
    expect(page.locator('#create-backup')).to_be_disabled()
    expect(page.locator('#backup-status')).to_contain_text('Criando e verificando')
    expect(page.locator('#backup-status')).to_contain_text('Não foi possível gerar', timeout=10000)
    expect(page.locator('#create-backup')).to_be_enabled()


def test_search_result_controls_pagination_reload_and_reset(page):
    page.locator('#result-limit').select_option('10')
    expect(page.locator('.article-card')).to_have_count(10)
    page.locator('#result-order').select_option('oldest')
    expect(page.locator('.article-title').first).to_have_text('Malware report 00')
    page.locator('#next').click()
    expect(page.locator('#page-number')).to_have_text('Página 2')
    expect(page.locator('.article-title').first).to_have_text('Malware report 10')
    page.reload()
    expect(page.locator('#result-limit')).to_have_value('10')
    expect(page.locator('#result-order')).to_have_value('oldest')
    expect(page.locator('.article-title').first).to_have_text('Malware report 10')
    page.locator('#result-limit').select_option('50')
    expect(page.locator('#page-number')).to_have_text('Página 1')
    expect(page.locator('.article-card')).to_have_count(27)
    page.locator('#result-period').select_option('today')
    expect(page.locator('.article-card')).to_have_count(0)
    page.locator('#clear-filters').click()
    expect(page.locator('#result-limit')).to_have_value('20')
    expect(page.locator('#result-order')).to_have_value('newest')
    expect(page.locator('#result-period')).to_have_value('all')
    expect(page.locator('.article-card')).to_have_count(20)


def test_exact_search_threshold_history_and_mobile_controls(page):
    expect(page.locator('#search-match')).to_be_disabled()
    page.locator('#search').fill('malwre')
    page.locator('#search').press('Enter')
    expect(page.locator('.article-card')).to_have_count(20)
    expect(page.locator('#fuzzy-threshold')).to_be_enabled()
    for invalid in ('101', ''):
        page.locator('#fuzzy-threshold').fill(invalid)
        page.locator('#fuzzy-threshold').press('Tab')
        assert not page.locator('#fuzzy-threshold').evaluate('(input) => input.checkValidity()')
        assert 'fuzzy_threshold=' not in page.url
        expect(page.locator('.article-card')).to_have_count(20)
    page.locator('#fuzzy-threshold').fill('100')
    page.locator('#fuzzy-threshold').press('Tab')
    expect(page.locator('.article-card')).to_have_count(0)
    page.locator('#fuzzy-threshold').fill('70')
    page.locator('#fuzzy-threshold').press('Tab')
    expect(page.locator('.article-card')).to_have_count(20)
    page.locator('#search-match').select_option('exact')
    expect(page.locator('.article-card')).to_have_count(0)
    expect(page.locator('#fuzzy-threshold')).to_be_disabled()
    page.reload()
    expect(page.locator('#search-match')).to_have_value('exact')
    expect(page.locator('#fuzzy-threshold')).to_have_value('70')
    expect(page.locator('.article-card')).to_have_count(0)
    page.go_back()
    expect(page.locator('#search-match')).to_have_value('fuzzy')
    expect(page.locator('.article-card')).to_have_count(20)
    page.set_viewport_size({'width': 390, 'height': 844})
    page.wait_for_timeout(300)
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.locator('#result-limit').select_option('100')
    expect(page.locator('.article-card')).to_have_count(27)


def test_invalid_url_controls_use_valid_defaults(page, frontend_server):
    page.goto(frontend_server + '/?q=malware&limit=-1&order=invalid&period=invalid&match=invalid&fuzzy_threshold=101')
    expect(page.locator('#result-limit')).to_have_value('20')
    expect(page.locator('#result-order')).to_have_value('newest')
    expect(page.locator('#result-period')).to_have_value('all')
    expect(page.locator('#search-match')).to_have_value('fuzzy')
    expect(page.locator('#fuzzy-threshold')).to_have_value('80')
    expect(page.locator('.article-card')).to_have_count(20)


def test_attack_mapping_distinguishes_article_references_from_catalog_context(page):
    page.get_by_role('button', name='Malware report 24', exact=True).click()
    expect(page.locator('.attack-details')).to_contain_text('MITRE ATT&CK 19.1')
    expect(page.locator('.attack-details')).to_contain_text('Técnicas e campanhas mencionadas')
    expect(page.locator('.attack-details')).to_contain_text('Técnicas e campanhas relacionadas no catálogo')
    expect(page.locator('.attack-group').first).to_contain_text('T1059.001')
    expect(page.locator('.attack-group').first).to_contain_text('C0001')
    expect(page.locator('.attack-group').nth(1).locator('a').first).to_have_attribute('href', re.compile(r'https://attack\.mitre\.org/(techniques|campaigns)/'))
    page.locator('.attack-relations summary').click()
    expect(page.locator('.attack-relations')).to_contain_text('não confirmam uso ou atribuição nesta notícia')
    expect(page.locator('.attack-relation').first).to_be_visible()
    expect(page.locator('#article-dialog img, #article-dialog script')).to_have_count(0)
    page.set_viewport_size({'width': 390, 'height': 844})
    page.wait_for_timeout(300)
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    assert page.locator('#article-dialog').evaluate('(dialog) => dialog.scrollWidth <= dialog.clientWidth')


def test_vulnerability_lookup_context_cache_and_mobile_layout(page):
    import json
    page.locator('.article-title').filter(has_text='Malware report 24').click()
    section = page.locator('.vulnerability-details')
    expect(section).to_be_visible()
    expect(section).to_contain_text('CVE-2026-1234')
    expect(section).to_contain_text('Ainda não consultado')
    requests = []
    def respond(route):
        requests.append(route.request)
        assert route.request.method == 'POST'
        assert route.request.headers['x-cyber-rss-request'] == '1'
        route.fulfill(json={'cve_id': 'CVE-2026-1234', 'status': 'ok', 'cached': True, 'stale': False,
                            'checked_at': '2026-10-10T12:00:00Z', 'retry_after': 0,
                            'source_url': 'https://www.cve.org/CVERecord?id=CVE-2026-1234',
                            'record': {'state': 'PUBLISHED', 'title': '<img src=x onerror="window.__cve_xss=1">',
                                       'description': 'Official vulnerability description.', 'cvss': [], 'cwes': ['CWE-79'],
                                       'affected': [{'vendor': 'Vendor', 'product': 'Product', 'default_status': 'unaffected',
                                                     'versions': [{'version': '1.0', 'lessThan': '2.0', 'status': 'affected'}]}],
                                       'references': ['https://example.com/fix', 'javascript:window.__cve_xss=1']}})
    page.route('**/vulnerabilities/CVE-2026-1234', respond)
    section.get_by_role('button', name='Consultar CVE').click()
    expect(section).to_contain_text('Official vulnerability description.')
    expect(section).to_contain_text('CVSS não informado')
    expect(section.locator('img')).to_have_count(0)
    assert page.evaluate('window.__cve_xss') is None
    section.get_by_text('Produtos, versões e referências').click()
    expect(section).to_contain_text('2.0')
    expect(section.locator('.vulnerability-references a')).to_have_count(1)
    assert len(requests) == 1
    page.set_viewport_size({'width': 390, 'height': 844})
    section.scroll_into_view_if_needed()
    assert page.locator('#article-dialog').evaluate('(e) => e.scrollWidth <= e.clientWidth')
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')


def test_postgres_external_backups_do_not_offer_sqlite_zip_controls(page):
    page.route('**/backups/status',lambda route:route.fulfill(json={'status':'unsupported','supported':False,'error':'Backups PostgreSQL externos.'}))
    page.route('**/backups',lambda route:route.fulfill(json={'items':[],'retention':None,'supported':False,'message':'Gerencie os backups PostgreSQL com seu provedor.'}))
    page.locator('#nav-backups').click()
    expect(page.locator('#create-backup')).to_be_hidden()
    expect(page.locator('#backups-retention')).to_contain_text('PostgreSQL')
    expect(page.locator('#backups-format-note')).to_contain_text('Retenção e restauração')
    expect(page.locator('#backups-format-note')).not_to_contain_text('ZIP')
    expect(page.locator('#backup-list')).to_be_empty()



def test_extended_feed_text_is_complete_in_details_and_short_in_list(page):
    card = page.locator('.article-card').filter(has=page.get_by_role('button', name='Malware report 24', exact=True))
    preview = card.locator('.article-summary')
    expect(preview).to_be_visible()
    assert len(preview.inner_text()) == 600
    expect(preview).not_to_contain_text('End of extended feed content.')
    card.get_by_role('button', name='Malware report 24', exact=True).click()
    expect(page.locator('.detail-summary')).to_contain_text('End of extended feed content.')
    assert len(page.locator('.detail-summary').inner_text()) > 2000
    page.reload()
    expect(page.locator('.detail-summary')).to_contain_text('End of extended feed content.')


def test_export_downloads_follow_search_and_current_page(page):
    page.get_by_label('Buscar artigos', exact=True).fill('malware')
    page.get_by_role('button', name='Buscar', exact=False).click()
    page.locator('#source').select_option('Source B')
    expect(page.locator('#article-list')).to_have_attribute('aria-busy', 'false')
    expect(page.locator('#export-json')).to_have_attribute('href', re.compile(r'category|source=Source\+B'))
    with page.expect_download() as info:
        page.locator('#export-json').click()
    download = info.value
    import json
    from pathlib import Path
    payload = json.loads(Path(download.path()).read_text())
    assert download.suggested_filename == 'cyber-rss-articles.json'
    assert payload['count'] == 13
    assert all(item['source'] == 'Source B' for item in payload['articles'])
