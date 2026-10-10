from __future__ import annotations

import argparse
import ipaddress
import os
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Literal
from collections import Counter

from fastapi import FastAPI, Query, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, StrictBool
from app.worker import CollectorBusy
from web_api.collection import CollectionController
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from config.paths import ARTICLE_DATABASE_FILE
from search.engine import SearchEngine
from services.search_service import SearchService
from storage.interfaces import ArticleRepository
from storage.sqlite_storage import SQLiteArticleRepository
from storage.utils import article_key, article_to_dict
from topics.algorithms.tfidf import TFIDFTopicExtractor
from topics.extractor import TopicExtractionService
from web_api.security import AccessMiddleware, SecuritySettings


class CollectionRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    force_refresh: StrictBool = True


def create_app(repository: ArticleRepository | None = None, *,
               database_file: Path = ARTICLE_DATABASE_FILE,
               security: SecuritySettings | None = None,
               collection_service_factory=None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        app.state.repository = (repository if repository is not None else
                                await run_in_threadpool(SQLiteArticleRepository, database_file))
        archive = getattr(app.state.repository, 'database_file', database_file)
        app.state.collection = CollectionController(archive, collection_service_factory)
        try:
            yield
        finally:
            await run_in_threadpool(app.state.collection.close)

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

    @app.get('/collection')
    def collection_status(response: Response):
        response.headers['Cache-Control'] = 'no-store'
        return app.state.collection.status()

    @app.post('/collection', status_code=202)
    def collect_now(body: CollectionRequest, request: Request):
        # A custom header prevents HTML forms and cross-origin browser requests
        # from starting a collection. Cross-origin preflights are not enabled.
        if (request.headers.get('x-cyber-rss-request') != '1' or
                request.headers.get('sec-fetch-site') == 'cross-site'):
            raise HTTPException(status_code=403, detail='Use a same-origin collection request')
        try:
            return app.state.collection.start(force_refresh=body.force_refresh)
        except CollectorBusy:
            raise HTTPException(status_code=409, detail='A collection is already running')

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
        return serialize(article)

    @app.get("/articles")
    def articles(category: str | None = Query(None, max_length=200),
                 source: str | None = Query(None, max_length=200),
                 tag: str | None = Query(None, max_length=200),
                 limit: int = Query(20, ge=1, le=100),
                 offset: int = Query(0, ge=0)):
        rows = app.state.repository.latest(category=category, source=source, tag=tag,
                                           limit=limit + 1, offset=offset)
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
               offset: int = Query(0, ge=0, le=10000)):
        service = SearchService(repository=app.state.repository, engine=SearchEngine())
        rows = service.search(keyword=q, category=category, source=source, tag=tag,
                              limit=offset + limit + 1)
        return {"items": [serialize(a) for a in rows[offset:offset + limit]],
                "limit": limit, "offset": offset, "has_more": len(rows) > offset + limit}

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
    if not loopback and (settings.credentials is None or not certificate):
        parser.error('Non-loopback listeners require authentication and TLS')
    uvicorn.run(create_app(database_file=args.database, security=settings), host=args.host, port=args.port,
                ssl_certfile=str(certificate) if certificate else None,
                ssl_keyfile=str(key) if key else None,
                proxy_headers=False, limit_concurrency=32, timeout_keep_alive=5)


if __name__ == "__main__":
    main()
