"""Browser tests: install .[dev,browser], then playwright install chromium."""
from datetime import datetime, timezone
import os
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
                        summary=f'Investigation of ransomware campaign {i}.', url=f'https://example.com/{i}',
                        tags=['ransomware' if i % 2 == 0 else 'research'], malware=['BlackEnergy'],
                        threat_actors=['APT28'], iocs=[IOC(IOCType.CVE, 'CVE-2026-1234')],
                        published=datetime(2026, 1, i + 1, tzinfo=timezone.utc)) for i in range(26)]
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
