from __future__ import annotations

import argparse
import ipaddress
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Literal
from collections import Counter

from fastapi import FastAPI, Query, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, StrictBool, Field, HttpUrl, field_validator
from app.worker import CollectorBusy, collector_lock
from app.container import ApplicationContainer
from config.feed_registry import FeedRegistry, FeedConflict, FeedNotFound
from config.paths import FEED_DIRECTORY
from web_api.collection import CollectionController
from web_api.backups import BackupController, BackupBusy, BackupDownloadResponse
from storage.backup import list_backups, export_backup
import sqlite3
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from config.paths import ARTICLE_DATABASE_FILE, ATTACK_MAPPING_CATALOG_FILE
from cti.attack_mapping import AttackCatalog
from cti.cve import normalize_cve
from services.vulnerability_service import VulnerabilityService
from search.engine import SearchEngine
from search.models import SearchOrder, SearchPeriod, SearchMatch
from services.search_service import SearchService
from services.export_service import ExportFormat, MEDIA_TYPES, export_articles
from alerts.outbox import AlertOutbox
from parser.models import IOCType
from storage.interfaces import ArticleRepository
from storage.factory import create_repository, is_postgres
from config.postgres_feed_registry import PostgreSQLFeedRegistry
from storage.utils import article_key, article_to_dict
from topics.algorithms.tfidf import TFIDFTopicExtractor
from topics.extractor import TopicExtractionService
from web_api.security import AccessMiddleware, SecuritySettings, listener_is_protected
from feeds.network import obviously_private_host, private_feeds_allowed
from config.structured_logging import configure_logging_from_environment


class CollectionRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    force_refresh: StrictBool = True


class CVELookupRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    refresh: StrictBool = False


class FeedInput(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=200)
    url: HttpUrl = Field(max_length=2048)
    category: str = Field(pattern=r'^[a-z][a-z0-9_]{0,63}$')
    description: str | None = Field(default=None, max_length=2000)
    enabled: StrictBool = True

    @field_validator('url')
    @classmethod
    def no_credentials(cls, value):
        if value.username or value.password:
            raise ValueError('Use a URL without embedded credentials')
        if value.host and obviously_private_host(value.host) and not private_feeds_allowed():
            raise ValueError('Use a feed URL on a public address')
        return value


def require_action(request: Request):
    if (request.headers.get('x-cyber-rss-request') != '1' or
            request.headers.get('sec-fetch-site') == 'cross-site'):
        raise HTTPException(status_code=403, detail='Use a same-origin action request')


def create_app(repository: ArticleRepository | None = None, *,
               database_file: Path = ARTICLE_DATABASE_FILE,
               security: SecuritySettings | None = None,
               collection_service_factory=None,
               feed_directory: Path = FEED_DIRECTORY,
               backup_directory: Path | None = None,
               attack_catalog_file: Path = ATTACK_MAPPING_CATALOG_FILE,
               vulnerability_service: VulnerabilityService | None = None,
               database_url: str | None = None) -> FastAPI:
    # uvicorn has configured its own loggers by the time the factory runs;
    # with CYBER_RSS_LOG_FORMAT=json they are rerouted through the JSON handler.
    configure_logging_from_environment(logging.INFO)
    @asynccontextmanager
    async def lifespan(app):
        app.state.repository = (repository if repository is not None else
                                await run_in_threadpool(create_repository, database_file=database_file, database_url=database_url))
        archive = getattr(app.state.repository, 'database_file', database_file)
        app.state.attack_catalog = await run_in_threadpool(AttackCatalog.load, attack_catalog_file)
        app.state.vulnerabilities = vulnerability_service or VulnerabilityService(Path(archive).parent / "cve-cache.sqlite3")
        postgres = is_postgres(app.state.repository)
        app.state.lock_target = app.state.repository if postgres else archive
        app.state.feed_registry = (PostgreSQLFeedRegistry(app.state.repository, feed_directory) if postgres
                                   else FeedRegistry(archive, feed_directory))
        app.state.collection = CollectionController(app.state.lock_target, collection_service_factory or (
            lambda: ApplicationContainer(
                database_file=archive, database_url=app.state.repository._database_url if postgres else '',
                config_directory=feed_directory).article_service))
        backup_path = backup_directory if backup_directory is not None else Path(
            os.environ.get('CYBER_RSS_BACKUP_DIR', str(archive.parent / 'backups')))
        app.state.backups = None if postgres else BackupController(archive, backup_path)
        try:
            yield
        finally:
            await run_in_threadpool(app.state.collection.close)
            if app.state.backups is not None:
                await run_in_threadpool(app.state.backups.close)

    app = FastAPI(title="Cyber RSS Reader", version="0.1.0", lifespan=lifespan)
    app.add_middleware(AccessMiddleware, settings=security if security is not None else SecuritySettings.from_environment())
    static_directory = Path(__file__).resolve().parent / 'static'
    app.mount('/assets', StaticFiles(directory=static_directory), name='assets')

    @app.get('/', include_in_schema=False)
    def frontend():
        return FileResponse(static_directory / 'index.html', headers={
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; "
                                       "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                                       "base-uri 'none'; frame-ancestors 'none'",
            'Referrer-Policy': 'no-referrer',
        })

    def serialize(article):
        return {"id": article_key(article), **article_to_dict(article)}

    @app.get('/backups')
    def backups(response: Response):
        response.headers['Cache-Control'] = 'no-store'
        if app.state.backups is None:
            return {'items': [], 'retention': None, 'supported': False, 'message': 'Gerencie os backups PostgreSQL com pg_dump ou com seu provedor de banco.'}
        return {'items': list_backups(app.state.backups.directory), 'retention': app.state.backups.keep}

    @app.get('/backups/status')
    def backup_status(response: Response):
        response.headers['Cache-Control'] = 'no-store'
        if app.state.backups is None:
            return {'status': 'unsupported', 'supported': False, 'error': 'Gerencie os backups PostgreSQL com pg_dump ou com seu provedor de banco.'}
        return app.state.backups.status()

    @app.post('/backups', status_code=202)
    def backup_now(request: Request):
        require_action(request)
        if app.state.backups is None:
            raise HTTPException(status_code=501, detail='Use backups PostgreSQL externos.')
        try:
            return app.state.backups.start()
        except BackupBusy:
            raise HTTPException(status_code=409, detail='Um backup manual já está em andamento.')

    @app.get('/backups/{backup_id}/download')
    def download_backup(backup_id: str):
        if app.state.backups is None:
            raise HTTPException(status_code=501, detail='Use backups PostgreSQL externos.')
        try:
            bundle = export_backup(app.state.backups.directory, backup_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail='Backup não encontrado. Atualize a lista.')
        except (ValueError, KeyError, TypeError, sqlite3.Error):
            raise HTTPException(status_code=409, detail='Backup inválido ou danificado. Escolha outra cópia.')
        except OSError:
            raise HTTPException(status_code=503, detail='Não foi possível preparar o download. Consulte os logs e tente novamente.')
        try:
            return BackupDownloadResponse(bundle, media_type='application/zip',
                                filename=Path(backup_id).with_suffix('.zip').name,
                                headers={'Cache-Control': 'no-store'})
        except BaseException:
            bundle.unlink(missing_ok=True)
            raise

    @app.get('/feed-config')
    def feed_config(response: Response):
        response.headers['Cache-Control'] = 'no-store'
        rows = app.state.feed_registry.list()
        return {'items': rows, 'categories': sorted({row['category'] for row in rows}),
                'enabled': sum(row['enabled'] for row in rows), 'total': len(rows)}

    def save_feed(body: FeedInput, request: Request, feed_id: str | None = None):
        require_action(request)
        try:
            with collector_lock(app.state.lock_target):
                return app.state.feed_registry.save(body.model_dump(mode='json'), feed_id=feed_id)
        except CollectorBusy:
            raise HTTPException(status_code=409, detail='Aguarde a coleta terminar antes de alterar os feeds.')
        except FeedConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except FeedNotFound:
            raise HTTPException(status_code=404, detail='Feed não encontrado.')

    @app.post('/feed-config', status_code=201)
    def add_feed(body: FeedInput, request: Request):
        return save_feed(body, request)

    @app.put('/feed-config/{feed_id}')
    def edit_feed(feed_id: str, body: FeedInput, request: Request):
        return save_feed(body, request, feed_id)

    @app.get('/collection')
    def collection_status(response: Response):
        response.headers['Cache-Control'] = 'no-store'
        return app.state.collection.status()

    @app.post('/collection', status_code=202)
    def collect_now(body: CollectionRequest, request: Request):
        # A custom header prevents HTML forms and cross-origin browser requests
        # from starting a collection. Cross-origin preflights are not enabled.
        require_action(request)
        try:
            return app.state.collection.start(force_refresh=body.force_refresh)
        except CollectorBusy:
            raise HTTPException(status_code=409, detail='A collection is already running')

    def cve_identifier(value):
        try:
            return normalize_cve(value)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

    @app.get('/vulnerabilities/{cve_id}')
    def cached_vulnerability(cve_id: str, response: Response):
        response.headers['Cache-Control'] = 'no-store'
        return app.state.vulnerabilities.cached(cve_identifier(cve_id))

    @app.post('/vulnerabilities/{cve_id}')
    def lookup_vulnerability(cve_id: str, body: CVELookupRequest, request: Request, response: Response):
        require_action(request)
        response.headers['Cache-Control'] = 'no-store'
        return app.state.vulnerabilities.lookup(cve_identifier(cve_id), refresh=body.refresh)

    @app.get("/health")
    def health():
        app.state.repository.latest(limit=1)
        return {"status": "ok"}

    @app.get('/filters')
    def filters():
        return app.state.repository.filters()

    @app.get('/articles/detail')
    def detail(id: str = Query(..., min_length=1, max_length=8192)):
        article = app.state.repository.get(id)
        if article is None:
            raise HTTPException(status_code=404, detail='Article not found')
        catalog = app.state.attack_catalog
        mapping = article.attack or (catalog.detect(article) if catalog else None)
        details = catalog.describe(mapping) if catalog else {
            'status': 'unavailable', 'catalog_version': article.attack.catalog_version if article.attack else None,
            'techniques': [], 'campaigns': [], 'relationships': []}
        return {**serialize(article), 'attack': asdict(mapping) if mapping else None, 'attack_details': details,
                'vulnerabilities': app.state.vulnerabilities.for_article(article)}

    @app.get('/exports/articles')
    def export_archive(format: ExportFormat = ExportFormat.json,
                       q: str | None = Query(None, min_length=1, max_length=500),
                       category: str | None = Query(None, max_length=200),
                       source: str | None = Query(None, max_length=200),
                       tag: str | None = Query(None, max_length=200),
                       ioc: str | None = Query(None, min_length=1, max_length=8192),
                       ioc_type: IOCType | None = None,
                       threat_actor: str | None = Query(None, min_length=1, max_length=200),
                       limit: int = Query(1000, ge=1, le=10000),
                       offset: int = Query(0, ge=0, le=1000000),
                       order: SearchOrder = SearchOrder.newest,
                       period: SearchPeriod = SearchPeriod.all,
                       match: SearchMatch = SearchMatch.fuzzy,
                       fuzzy_threshold: int = Query(80, ge=0, le=100)):
        service = SearchService(repository=app.state.repository, engine=SearchEngine())
        try:
            rows = service.search(keyword=q, category=category, source=source, tag=tag,
                ioc=ioc, ioc_type=ioc_type, threat_actor=threat_actor, limit=limit, offset=offset,
                newest=order == SearchOrder.newest, oldest=order == SearchOrder.oldest,
                today=period == SearchPeriod.today, last_week=period == SearchPeriod.week,
                match_mode=match, fuzzy_threshold=fuzzy_threshold)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        return Response(export_articles(rows, format), media_type=MEDIA_TYPES[format],
            headers={'Content-Disposition': f'attachment; filename="cyber-rss-articles.{format.value}"',
                     'Cache-Control': 'no-store', 'X-Export-Count': str(len(rows)),
                     'X-Export-Limit': str(limit), 'X-Export-Offset': str(offset)})

    @app.get('/alerts/status')
    def alerts_status(response: Response):
        response.headers['Cache-Control'] = 'no-store'
        try:
            return AlertOutbox(app.state.repository).status()
        except ValueError:
            raise HTTPException(status_code=501, detail='Alerts require SQLite or PostgreSQL storage')

    @app.get("/articles")
    def articles(category: str | None = Query(None, max_length=200),
                 source: str | None = Query(None, max_length=200),
                 tag: str | None = Query(None, max_length=200),
                 limit: int = Query(20, ge=1, le=100),
                 offset: int = Query(0, ge=0),
                 order: SearchOrder = SearchOrder.newest,
                 period: SearchPeriod = SearchPeriod.all):
        if order == SearchOrder.newest and period == SearchPeriod.all:
            rows = app.state.repository.latest(category=category, source=source, tag=tag,
                                               limit=limit + 1, offset=offset)
        else:
            service = SearchService(repository=app.state.repository, engine=SearchEngine())
            rows = service.search(category=category, source=source, tag=tag,
                                  limit=limit + 1, offset=offset,
                                  newest=order == SearchOrder.newest, oldest=order == SearchOrder.oldest,
                                  today=period == SearchPeriod.today, last_week=period == SearchPeriod.week)
        return {"items": [serialize(a) for a in rows[:limit]],
                "limit": limit, "offset": offset, "has_more": len(rows) > limit}

    @app.get("/feeds")
    def feeds(status: Literal['collecting', 'success', 'error'] | None = None,
              limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0)):
        rows = app.state.repository.feed_status()
        counts = Counter(row['status'] for row in rows)
        if status:
            rows = [row for row in rows if row['status'] == status]
        return {'items': rows[offset:offset + limit], 'limit': limit, 'offset': offset,
                'has_more': len(rows) > offset + limit,
                'summary': {'total': sum(counts.values()),
                            **{key: counts[key] for key in ('collecting', 'success', 'error')}}}

    @app.get("/search")
    def search(q: str = Query(..., min_length=1, max_length=500),
               category: str | None = Query(None, max_length=200),
               source: str | None = Query(None, max_length=200),
               tag: str | None = Query(None, max_length=200),
               limit: int = Query(20, ge=1, le=100),
               offset: int = Query(0, ge=0, le=10000),
               order: SearchOrder = SearchOrder.newest,
               period: SearchPeriod = SearchPeriod.all,
               match: SearchMatch = SearchMatch.fuzzy,
               fuzzy_threshold: int = Query(80, ge=0, le=100)):
        service = SearchService(repository=app.state.repository, engine=SearchEngine())
        rows = service.search(keyword=q, category=category, source=source, tag=tag,
                              limit=limit + 1, offset=offset,
                              newest=order == SearchOrder.newest, oldest=order == SearchOrder.oldest,
                              today=period == SearchPeriod.today, last_week=period == SearchPeriod.week,
                              match_mode=match, fuzzy_threshold=fuzzy_threshold)
        return {"items": [serialize(a) for a in rows[:limit]],
                "limit": limit, "offset": offset, "has_more": len(rows) > limit}

    @app.get("/topics")
    def topics(limit: int = Query(20, ge=1, le=100)):
        extractor = TopicExtractionService(TFIDFTopicExtractor())
        return {"items": [asdict(t) for t in extractor.extract(
            app.state.repository.load(), limit=limit)]}

    return app


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="Serve the article API and manual collection controls.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--database", type=Path, default=ARTICLE_DATABASE_FILE)
    parser.add_argument("--ssl-certfile", type=Path)
    parser.add_argument("--ssl-keyfile", type=Path)
    args = parser.parse_args()
    settings = SecuritySettings.from_environment()
    certificate = args.ssl_certfile or os.environ.get('CYBER_RSS_TLS_CERT_FILE')
    key = args.ssl_keyfile or os.environ.get('CYBER_RSS_TLS_KEY_FILE')
    if bool(certificate) != bool(key):
        parser.error('Both TLS certificate and key are required')
    try:
        loopback = ipaddress.ip_address(args.host).is_loopback
    except ValueError:
        loopback = args.host == 'localhost'
    if not loopback and not listener_is_protected(settings, tls=bool(certificate)):
        parser.error('Non-loopback listeners require authentication and TLS '
                     '(direct, or terminated by a proxy listed in CYBER_RSS_TRUSTED_PROXIES)')
    uvicorn.run(create_app(database_file=args.database, security=settings), host=args.host, port=args.port,
                ssl_certfile=str(certificate) if certificate else None,
                ssl_keyfile=str(key) if key else None,
                proxy_headers=False, limit_concurrency=32, timeout_keep_alive=5)


if __name__ == "__main__":
    main()
