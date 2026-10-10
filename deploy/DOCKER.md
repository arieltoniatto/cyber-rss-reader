# Run locally with Docker Compose

Docker runs the same installed Python package in three containers: `api` serves
the browser interface and manual collection controls, `worker` collects feeds immediately and every six hours
after each cycle, and `backup` creates a verified snapshot at startup and every
24 hours afterward, keeping 14 snapshots. Backup failures retry after five
minutes. The collector and backup wait for the API/archive healthcheck before
starting. Containers run as user `10001`, with a read-only root filesystem;
the runtime archive is writable in a shared local Docker volume.

## Start

Use Docker Engine 28+ (or current Docker Desktop) with Docker Compose, then run
from the repository:

```bash
docker compose up -d --build
```

Open **http://127.0.0.1:8001**. No certificate or login is needed. Port 8001
lets Docker coexist with the existing systemd API on port 8000. The container
listens on its internal port 8000, but Compose publishes it only on host
`127.0.0.1`. This is the Docker local-only setup; the API command used for
ordinary native execution still requires TLS/authentication for external binds.
The image contains feeds, enrichment catalogs and static assets, so no checkout
or node frontend tooling is needed inside the runtime container.

If Linux reports permission denied on `/var/run/docker.sock`, run the Docker
commands with `sudo`, or configure Docker access for your account. On Windows,
enable Docker Desktop's WSL integration for the distribution where you run the
commands. Use a local Docker daemon: the published localhost address belongs
to the Docker host.

Inspect startup, feed outcomes and logs:

```bash
docker compose ps
docker compose logs --tail=50 api worker backup
```

The first collection takes time; the interface may initially show no articles.
Reload the page when collection completes. To collect again now:

```bash
docker compose restart worker
```

A manual backup can also be created while the API/worker run:

```bash
docker compose exec backup python -m tools.backup_database --keep 14
```

## Data and lifecycle

The project-scoped `archive` named volume mounts at `/runtime` in all three
containers. It stores `/runtime/data/articles.sqlite3`, its WAL files and
`/runtime/data/backups/`. The existing host database is **not** mounted or
modified; a new Docker volume starts an independent archive. SQLite and locks
must remain on a local volume shared by these containers, not a network file
share or separate Docker hosts.

Stop the containers while preserving the archive:

```bash
docker compose down
```

Start them again with `docker compose up -d`. Do not add `--volumes` or `-v` to
`down` when you want to preserve data: those options delete the named volume.
After source/dependency updates, use `docker compose up -d --build`. Containers
restart after daemon/host restarts unless you stopped them explicitly; Docker
itself must start on the host. Scheduled backups resume immediately on startup.
The Docker backup interval is 24 hours between successful snapshots rather than
the systemd timer's calendar-midnight schedule.

To replace the native services rather than coexist with them, stop/disable the
native services, then start Docker on port 8000:

```bash
systemctl --user disable --now cyber-rss-api.service cyber-rss-worker.service cyber-rss-backup.timer
CYBER_RSS_WEB_PORT=8000 docker compose up -d --build
```

For repeated commands on this port, keep `CYBER_RSS_WEB_PORT=8000` exported in
the terminal (with sudo, use `sudo env CYBER_RSS_WEB_PORT=8000 docker compose ...`).
To return to native operation, stop Compose, then enable the three user services.
Their original archive remains available independently of the Docker volume.

## Import the existing archive (optional)

Before the first Docker startup, create a verified snapshot with the existing
local environment:

```bash
.venv/bin/python -m tools.backup_database
docker compose build api
```

Substitute the snapshot filename printed by that command below. This temporary
root container reads the host backup directory **read-only**, copies the
snapshot/manifest into its temporary filesystem, and restores only into a new
archive in the Docker volume. The added capabilities allow reading private
backup files and assigning the restored file to the regular container user.
It refuses an existing destination; never delete an existing archive just to
make import succeed. If Docker has already run, use a separate Compose project
with `-p cyber-rss-import` consistently to get a new named volume.

```bash
docker compose run --rm --no-deps -T --user 0:0 \
  --cap-add DAC_OVERRIDE --cap-add CHOWN \
  -v "$PWD/data/backups:/source:ro" api python - articles-TIMESTAMP-ID.sqlite3 <<'PY'
from pathlib import Path
import os
import shutil
import sys
import tempfile
from storage.backup import restore_backup

source = Path('/source') / sys.argv[1]
with tempfile.TemporaryDirectory() as directory:
    copied = Path(directory) / source.name
    shutil.copyfile(source, copied)
    shutil.copyfile(source.with_suffix('.json'), copied.with_suffix('.json'))
    restored = restore_backup(copied, Path('/runtime/data/articles.sqlite3'))
    os.chown(restored, 10001, 10001)
    print('Archive restored:', restored)
PY
docker compose up -d
```

To keep collected history consistent when switching, stop the native worker
before creating the final snapshot. Its original archive is retained for rollback.

Build context inputs are allowlisted in `.dockerignore`; host databases,
credentials, `.env` files, generated certificates, logs and old backup copies
are not sent to the build. Article snapshots remain on the same Docker host;
copy snapshot/manifest pairs elsewhere if you need protection against disk loss.

References: [Compose readiness dependencies](https://docs.docker.com/compose/how-tos/startup-order/),
[Docker local port publishing](https://docs.docker.com/engine/network/port-publishing/),
and [persistent volumes](https://docs.docker.com/engine/storage/volumes/).
