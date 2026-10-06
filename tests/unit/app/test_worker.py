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
async def test_once_runs_one_forced_update():
    update = AsyncMock()
    await collect(SimpleNamespace(article_service=SimpleNamespace(update=update)), interval=1, once=True)
    update.assert_awaited_once_with(force_refresh=True)


@pytest.mark.asyncio
async def test_failed_once_propagates_error():
    update = AsyncMock(side_effect=ValueError("failed"))
    with pytest.raises(ValueError):
        await collect(SimpleNamespace(article_service=SimpleNamespace(update=update)), interval=1, once=True)


@pytest.mark.asyncio
async def test_periodic_collection_survives_failure():
    update = AsyncMock(side_effect=[ValueError("failed"), None])
    container = SimpleNamespace(article_service=SimpleNamespace(update=update))
    with patch("app.worker.asyncio.sleep", new=AsyncMock(side_effect=[None, KeyboardInterrupt])):
        with pytest.raises(KeyboardInterrupt):
            await collect(container, interval=1, once=False)
    assert update.await_count == 2
