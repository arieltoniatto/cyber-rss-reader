"""Bounded outgoing HTTP delivery without logging credential-bearing URLs."""
import asyncio
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, HTTPRedirectHandler, build_opener

from alerts.outbox import AlertOutbox


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send(destination, event, timeout):
    url, token, chat = destination.credentials()
    headers = {'Content-Type': 'application/json', 'User-Agent': 'CyberRSSReader/1.0',
               'Idempotency-Key': event['id']}
    payload = event
    if destination.kind == 'telegram':
        article = event['article']
        # Plain text: no HTML/Markdown interpretation or external preview fetching.
        title = article['title'][:500]
        source = article['source'][:200]
        link = article['url'][:2000]
        summary = article['summary'][:600]
        text = f"{title}\n{source}\n{link}\n{summary}".strip()
        payload = {'chat_id': chat, 'text': text, 'link_preview_options': {'is_disabled': True}}
    elif token:
        headers['Authorization'] = 'Bearer '+token
    request = Request(url, data=json.dumps(payload, ensure_ascii=False).encode(), headers=headers, method='POST')
    try:
        with build_opener(NoRedirect()).open(request, timeout=timeout) as response:
            if not 200 <= response.status < 300:
                return f'HTTP {response.status}'
            if destination.kind == 'telegram':
                result = json.loads(response.read(65536))
                if result.get('ok') is not True:
                    return 'Telegram rejected the message'
    except HTTPError as exc:
        code = exc.code
        exc.close()
        return f'HTTP {code}'
    except (URLError, OSError, ValueError, TypeError):
        return 'Delivery transport or response error'
    return None


class AlertService:
    def __init__(self, repository, settings, sender=send):
        self.settings = settings
        self.outbox = AlertOutbox(repository)
        self.sender = sender

    def dispatch(self):
        destinations = {item.id: item for item in self.settings.active}
        result = {'sent': 0, 'failed': 0}
        for _ in range(self.settings.batch_size):
            claimed = self.outbox.claim(self.settings)
            if claimed is None:
                break
            key, state = claimed
            try:
                error = self.sender(destinations[state['destination']], state['event'], self.settings.timeout_seconds)
            except Exception:
                error = 'Delivery configuration or transport error'
            self.outbox.finish(key, state, error=error, max_attempts=self.settings.max_attempts)
            result['failed' if error else 'sent'] += 1
        return result

    async def after_collection(self):
        if self.settings.active:
            await asyncio.to_thread(self.dispatch)
