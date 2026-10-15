# Outgoing article alerts

Alerts are opt-in. Without `CYBER_RSS_ALERT_CONFIG`, no events are queued and
no outgoing alert requests are made. SQLite and PostgreSQL share the same
implementation; the legacy JSON adapter does not support alerts.

Copy `alerts.example.json` to a private runtime file (for example,
`data/alerts.json`), adjust the rules, and enable the destinations you want.
The example disables both destinations. Set the same configuration and
credential variables for the CLI, API and worker:

```bash
export CYBER_RSS_ALERT_CONFIG="$PWD/data/alerts.json"
export CYBER_RSS_WEBHOOK_URL='https://your-endpoint.example/alerts'
export CYBER_RSS_WEBHOOK_TOKEN='YOUR_PRIVATE_BEARER_TOKEN'
export CYBER_RSS_TELEGRAM_TOKEN='YOUR_BOT_TOKEN'
export CYBER_RSS_TELEGRAM_CHAT_ID='YOUR_CHAT_ID'
```

Use `.env.services` for existing user services and restart API/worker. Keep
runtime config/credentials outside Git. The JSON file holds environment-variable
names, not credentials. A webhook's `token_env` is optional; remove it if the
receiver does not require bearer authentication. HTTP is allowed for local
receivers; public destinations should use HTTPS. Redirects are not followed.

## Matching and enqueueing

Each destination accepts `categories`, `sources`, `tags`, `threat_actors` and
`ioc_types` arrays under `rules`. Rules are exact and case-insensitive. Values
within a list use OR; different lists use AND. Empty lists impose no restriction.
For example, the Telegram example requires both APT28 and an extracted CVE.
Omit all rules to match every newly collected article.

Only previously unknown article IDs discovered by a normal collection enqueue
alerts. Existing history is not backfilled; updates to known articles, opening
the archive, imports, explicit saves, cache hits and exports do not alert. On an
empty archive the first collection can enqueue all matching entries: use filters
or collect your initial baseline before enabling alerts.

Queue entries commit atomically with the articles and feed outcomes. One event
per article ID and destination ID is enforced. Alert data is stored under
`alerts:v1:*` in archive metadata and included in archive backups/imports. URL
and token values are never persisted in queue records. Successful deliveries
retain a compact receipt after clearing the payload; receipts survive article
retention and prevent reimported IDs from sending again. Receipts are retained
indefinitely, so plan storage for long-running installations.

Do not reuse a destination ID for an unrelated receiver. Changing the URL behind
an existing ID redirects its queued events to that new URL. Disabling/removing
a destination pauses its queue; re-enabling the same ID resumes it.

## Webhook payload

The receiver gets a JSON POST:

```json
{
  "schema_version": 1,
  "id": "stable-sha256-event-id",
  "type": "article.created",
  "created_at": "2026-10-15T12:00:00+00:00",
  "article": {
    "id": "article-id",
    "title": "Research report",
    "source": "Research",
    "url": "https://source.example/report",
    "summary": "",
    "iocs": [],
    "threat_actors": [],
    "malware": [],
    "cve_ids": []
  }
}
```

The actual article includes all other exported article fields. `summary` is
empty by default; `include_summary: true` includes at most 600 characters.
The `Idempotency-Key` HTTP header equals the event ID. Receivers should deduplicate
by it. Any 2xx response acknowledges a webhook; redirects and other statuses fail.
An optional token is sent as `Authorization: Bearer ...`.

## Telegram

Create a bot with BotFather, start a conversation with it (or add it to your
chosen group/channel), and obtain that destination's chat ID. Configure the bot
token and chat ID in the variables named by `token_env` and `chat_id_env`.
The bot must have permission to send messages to that destination.

Delivery uses [Telegram Bot API sendMessage](https://core.telegram.org/bots/api#sendmessage)
with plain text, bounded title/source/link/summary and disabled link previews.
No HTML or Markdown mode is enabled. Telegram must return `ok: true` for success.
No live alert is sent during installation or tests.

## Delivery, retries and inspection

After each real collection, the app dispatches up to `batch_size` due entries
(default 20, maximum 100). Sending happens after the archive transaction commits.
Delivery failures never turn successful collection outcomes into failures.
A request has a bounded timeout (default 5 seconds, maximum 30).

```bash
rss-alerts --status             # Counts/errors only, no sending (default)
rss-alerts --dispatch           # Explicitly send one due batch
rss-alerts --watch --interval 60 # Independent delivery loop; stop with Ctrl+C
rss-alerts --retry-failed       # Requeue terminal failures without sending
```

Automatic attempts also happen at the next collection. For faster retries or a
large queue, run the independent loop with the same config/backend. Each event
has at most `max_attempts` attempts (default 3), with exponential delays starting
at 60 seconds and capped at an hour. Failed attempts expose only sanitized error
messages, never credential-bearing URLs or response bodies. `GET /alerts/status`
returns counts and up to 20 sanitized errors under normal API authentication.

Workers claim individual entries using database locks and expiring leases;
crashed senders can be recovered after 120 seconds. Delivery is at least once:
a crash after the receiver accepts a message but before the receipt commits can
cause a duplicate. Webhooks can use the event ID to suppress it; Telegram has
no equivalent idempotency key. Restoring an older database backup can replay
deliveries that occurred after that backup.

## Docker

Both Compose stacks pass the opt-in config and credential variables to the app
services. The config path must exist **inside** the container, for example
`/runtime/alerts.json`. Put the file on the existing runtime volume or use an
override with a read-only bind mount. Store variables in your ignored `.env` or
configure the deployment environment, then recreate API/worker. Environment
credentials are visible to Docker administrators; use your deployment's secret
management when operating beyond a personal machine.

An optional delivery loop can run with the same environment/runtime volume:

```bash
docker compose run --rm worker rss-alerts --watch --interval 60
```
