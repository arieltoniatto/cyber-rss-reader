"""Non-secret alert configuration; credentials are resolved from environment variables."""
import json
import os
from pathlib import Path
import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field
from parser.models import IOCType


class Rules(BaseModel):
    model_config = ConfigDict(extra='forbid')
    categories: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    ioc_types: list[IOCType] = Field(default_factory=list)

    def matches(self, article):
        pairs = [(self.categories, [article.category] if article.category else []),
                 (self.sources, [article.source]), (self.tags, article.tags),
                 (self.threat_actors, article.threat_actors),
                 (self.ioc_types, [ioc.type for ioc in article.iocs])]
        return all(not wanted or {v.casefold() for v in wanted} & {v.casefold() for v in actual}
                   for wanted, actual in pairs)


class Destination(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    id: str = Field(pattern=r'^[a-zA-Z0-9_-]{1,64}$')
    kind: Literal['webhook', 'telegram'] = 'webhook'
    enabled: bool = True
    url_env: str | None = None
    token_env: str | None = None
    chat_id_env: str | None = None
    include_summary: bool = False
    rules: Rules = Field(default_factory=Rules)

    def credentials(self):
        def value(name):
            if not name or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) or not os.environ.get(name, '').strip():
                raise ValueError(f'Missing or invalid environment variable for alert destination {self.id}')
            return os.environ[name].strip()
        if self.kind == 'telegram':
            token, chat = value(self.token_env), value(self.chat_id_env)
            if not re.fullmatch(r'[0-9]+:[A-Za-z0-9_-]+', token):
                raise ValueError(f'Invalid Telegram token for destination {self.id}')
            return f'https://api.telegram.org/bot{token}/sendMessage', None, chat
        url = value(self.url_env)
        try:
            parsed = urlsplit(url)
            valid = parsed.scheme in ('http', 'https') and parsed.hostname and not parsed.username and not parsed.password and not parsed.fragment
        except ValueError:
            valid = False
        if not valid or any(ord(c) < 33 for c in url):
            raise ValueError(f'Invalid webhook URL for destination {self.id}')
        token = value(self.token_env) if self.token_env else None
        if token and any(c in token for c in '\r\n'):
            raise ValueError(f'Invalid bearer token for destination {self.id}')
        return url, token, None


class AlertSettings(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    destinations: list[Destination] = Field(default_factory=list, max_length=20)
    timeout_seconds: int = Field(default=5, ge=1, le=30)
    max_attempts: int = Field(default=3, ge=1, le=10)
    batch_size: int = Field(default=20, ge=1, le=100)

    @property
    def active(self):
        return [destination for destination in self.destinations if destination.enabled]

    @classmethod
    def from_environment(cls):
        path = os.environ.get('CYBER_RSS_ALERT_CONFIG')
        if not path:
            return cls()
        try:
            settings = cls.model_validate(json.loads(Path(path).read_text()))
        except (ValueError, OSError):
            # Pydantic errors can include input values; keep secrets out of logs.
            raise ValueError('Invalid CYBER_RSS_ALERT_CONFIG file') from None
        if len({item.id for item in settings.destinations}) != len(settings.destinations):
            raise ValueError('Alert destination IDs must be unique')
        for destination in settings.active:
            destination.credentials()
        return settings
