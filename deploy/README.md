# Continuous local operation

The API, worker and daily backup run as **user systemd services**. They use the
existing Python environment and one persistent archive. For personal use on
this computer, open `http://127.0.0.1:8000`. The API binds only to loopback and
needs no login, certificate or Windows LAN forwarding. The worker and backup
timer continue independently of the browser. Optional protected LAN access is
documented in [HTTPS.md](HTTPS.md).

## Setup

From the repository root:

```bash
.venv/bin/python -m pip install -e '.[web]'
.venv/bin/python deploy/configure_services.py
```

Review `deploy/generated/` and `.env.services`. By default,
`CYBER_RSS_DATA_DIR` is the absolute repository root, so the services use the
existing `data/articles.sqlite3`. No database is moved or replaced. A dedicated
runtime directory or a different backup volume can be selected in
`.env.services` before starting:

```ini
CYBER_RSS_DATA_DIR=/absolute/persistent/runtime
CYBER_RSS_BACKUP_DIR=/absolute/persistent/backups
PYTHONUNBUFFERED=1
```

The runtime directory must already contain the intended `data/articles.sqlite3`.
The default backup location is `data/backups` within the runtime directory.
These are plain systemd environment values; the file is not executed as a shell
script. Keep the code and `.venv` at their rendered absolute paths. Regenerate
and review the units if the project is moved. The renderer refuses to overwrite
different existing configuration; use a new output directory to compare changes.

Install and start the reviewed units:

```bash
.venv/bin/python deploy/configure_services.py --install
systemctl --user daemon-reload
systemctl --user enable --now cyber-rss-api.service cyber-rss-worker.service cyber-rss-backup.timer
systemctl --user start cyber-rss-backup.service
```

For operation after logout and at boot, enable lingering for your user:

```bash
loginctl enable-linger "$USER"
loginctl show-user "$USER" -p Linger
```

The API and worker restart automatically after unexpected exits. The worker
collects immediately and then waits six hours after each completed cycle. The
backup timer runs daily with up to 15 minutes of randomized delay and catches up
on missed calendar activations when restarted. These settings use the
[systemd service](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.service.xml)
and [timer](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.timer.xml)
mechanisms. Port, interval and retention can be selected with renderer options
`--port`, `--interval` (seconds), and `--keep`.

## Monitor and maintain

```bash
systemctl --user status cyber-rss-api.service cyber-rss-worker.service
systemctl --user list-timers cyber-rss-backup.timer
journalctl --user -u cyber-rss-api.service -n 50
journalctl --user -u cyber-rss-worker.service -n 50
journalctl --user -u cyber-rss-backup.service -n 50
```

The journal collects service logs; its storage/retention is managed by the host.
Use `/health` to check API/archive access and `/feeds` or the browser feed view
to check collection outcomes. A worker process being active does not guarantee
every feed succeeded. Changes to `.env.services` take effect when the affected
services restart. Code updates should be followed by tests and service restarts:

```bash
systemctl --user restart cyber-rss-api.service cyber-rss-worker.service
```

To stop continuous operation (without deleting data):

```bash
systemctl --user disable --now cyber-rss-api.service cyber-rss-worker.service cyber-rss-backup.timer
```

## Backup and recovery

Create a manual snapshot:

```bash
.venv/bin/rss-backup --database data/articles.sqlite3 --directory data/backups --keep 14
```

The backup uses [SQLite's online backup API](https://docs.python.org/3.12/library/sqlite3.html#sqlite3.Connection.backup),
so committed WAL data is included while readers/writers remain online. Each
snapshot is checked for SQLite integrity, includes articles and feed metadata,
and is published with a SHA-256 manifest. Backup files use mode `0600`. Retention
removes only older complete snapshots created by this tool, after the new one
has been verified. Failed backups preserve previous snapshots. Keep the SQLite
file **and its matching JSON manifest** together.

Validate a restore into a **new** runtime directory:

```bash
.venv/bin/rss-restore \
  --backup data/backups/articles-TIMESTAMP-ID.sqlite3 \
  --output /absolute/recovered-runtime/data/articles.sqlite3
```

The restore verifies the manifest/checksum, schema, integrity and table counts.
It refuses an existing destination or WAL/SHM sidecars, and never overwrites the
live archive. After validating the recovered archive, stop the API and worker,
update `CYBER_RSS_DATA_DIR` in `.env.services` to the recovered runtime, and
start them again. Keep the original runtime for rollback. If
`CYBER_RSS_BACKUP_DIR` was overridden, review it as part of recovery. Manual CLI
commands must use the same runtime setting or an explicit `--database`.

Daily backups on the same disk protect against logical/operational mistakes,
but not disk loss. Set `CYBER_RSS_BACKUP_DIR` to a separately mounted backup
volume, or replicate complete snapshot/manifest pairs to separate storage.
An existing mount should be checked before relying on that destination.
