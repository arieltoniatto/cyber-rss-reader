from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.worker import collect, collector_lock


def test_worker_lock_excludes_second_collector_and_releases(tmp_path):
    database = tmp_path / "archive.sqlite3"
    with collector_lock(database):
        with pytest.raises(RuntimeError, match="already running"):
            with collector_lock(database):
                pass
    with collector_lock(database):
        pass


@pytest.mark.asyncio
async def test_once_runs_one_forced_update(tmp_path):
    update = AsyncMock()
    await collect(SimpleNamespace(article_service=SimpleNamespace(update=update)), interval=1, once=True, database_file=tmp_path / "archive.sqlite3")
    update.assert_awaited_once_with(force_refresh=True)


@pytest.mark.asyncio
async def test_failed_once_propagates_error(tmp_path):
    update = AsyncMock(side_effect=ValueError("failed"))
    with pytest.raises(ValueError):
        await collect(SimpleNamespace(article_service=SimpleNamespace(update=update)), interval=1, once=True, database_file=tmp_path / "archive.sqlite3")


@pytest.mark.asyncio
async def test_periodic_collection_survives_failure(tmp_path):
    update = AsyncMock(side_effect=[ValueError("failed"), None])
    container = SimpleNamespace(article_service=SimpleNamespace(update=update))
    with patch("app.worker.asyncio.sleep", new=AsyncMock(side_effect=[None, KeyboardInterrupt])):
        with pytest.raises(KeyboardInterrupt):
            await collect(container, interval=1, once=False, database_file=tmp_path / "archive.sqlite3")
    assert update.await_count == 2


@pytest.mark.asyncio
async def test_worker_releases_collection_lock_while_sleeping(tmp_path):
    database = tmp_path / 'archive.sqlite3'
    async def update(**kwargs):
        with pytest.raises(RuntimeError):
            with collector_lock(database):
                pass
    async def sleep(interval):
        with collector_lock(database):
            pass
        raise KeyboardInterrupt
    container = SimpleNamespace(article_service=SimpleNamespace(update=update))
    with patch('app.worker.asyncio.sleep', new=sleep):
        with pytest.raises(KeyboardInterrupt):
            await collect(container, interval=1, once=False, database_file=database)


@pytest.mark.asyncio
async def test_busy_once_worker_does_not_start_another_update(tmp_path):
    database = tmp_path / 'archive.sqlite3'
    update = AsyncMock()
    with collector_lock(database):
        with pytest.raises(RuntimeError):
            await collect(SimpleNamespace(article_service=SimpleNamespace(update=update)),
                          interval=1, once=True, database_file=database)
    update.assert_not_awaited()
