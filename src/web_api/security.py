"""Authentication and bounded request budgets for the single-process API."""
import base64
import binascii
from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import time

from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse


def password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode('utf-8'), salt=salt, n=16384, r=8, p=1, dklen=32)


def create_credentials(username: str, password: str) -> dict:
    if not username or ':' in username or any(ord(char) < 32 or ord(char) == 127 for char in username) or len(username.encode('utf-8')) > 128:
        raise ValueError('Username must contain 1–128 bytes and no colon')
    if len(password) < 16 or len(password.encode('utf-8')) > 1024:
        raise ValueError('Password must contain at least 16 characters and at most 1024 bytes')
    salt = secrets.token_bytes(16)
    return {'username': username, 'salt': salt.hex(), 'hash': password_hash(password, salt).hex()}


@dataclass(frozen=True)
class SecuritySettings:
    credentials: dict | None = None
    per_minute: int = 120
    burst: int = 30
    global_per_minute: int = 600
    global_burst: int = 60
    max_clients: int = 10000

    def __post_init__(self):
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in
               (self.per_minute, self.burst, self.global_per_minute, self.global_burst, self.max_clients)):
            raise ValueError('Request limits must be positive integers')
        if self.credentials is not None:
            user = self.credentials.get('username')
            if not isinstance(user, str) or not user or ':' in user or any(ord(char) < 32 or ord(char) == 127 for char in user) or len(user.encode('utf-8')) > 128:
                raise ValueError('Invalid authentication username')
            if len(bytes.fromhex(self.credentials['salt'])) != 16 or len(bytes.fromhex(self.credentials['hash'])) != 32:
                raise ValueError('Invalid authentication salt or hash')

    @classmethod
    def from_environment(cls):
        path = os.environ.get('CYBER_RSS_AUTH_FILE')
        credentials = None
        if path:
            file = Path(path)
            if file.stat().st_mode & 0o077:
                raise ValueError('Authentication file must have permissions 0600')
            credentials = json.loads(file.read_text())
        return cls(credentials=credentials,
                   per_minute=int(os.environ.get('CYBER_RSS_RATE_PER_MINUTE', '120')),
                   burst=int(os.environ.get('CYBER_RSS_RATE_BURST', '30')),
                   global_per_minute=int(os.environ.get('CYBER_RSS_RATE_GLOBAL_PER_MINUTE', '600')),
                   global_burst=int(os.environ.get('CYBER_RSS_RATE_GLOBAL_BURST', '60')))


class RequestBudget:
    """Token buckets; never evict a recent client into a fresh allowance."""
    def __init__(self, settings: SecuritySettings, clock=time.monotonic):
        self.settings = settings
        self.clock = clock
        self.clients = OrderedDict()
        self.global_bucket = (float(settings.global_burst), clock())

    @staticmethod
    def refill(bucket, now, rate, burst):
        tokens, previous = bucket
        return min(float(burst), tokens + max(0, now - previous) * rate / 60)

    def allow(self, client: str) -> int:
        now = self.clock()
        settings = self.settings
        idle = settings.burst * 60 / settings.per_minute
        while self.clients:
            key, (_, previous) = next(iter(self.clients.items()))
            if now - previous < idle:
                break
            del self.clients[key]
        if client not in self.clients and len(self.clients) >= settings.max_clients:
            return 1
        bucket = self.clients.get(client, (float(settings.burst), now))
        tokens = self.refill(bucket, now, settings.per_minute, settings.burst)
        global_tokens = self.refill(self.global_bucket, now, settings.global_per_minute, settings.global_burst)
        self.clients[client] = (tokens, now)
        self.clients.move_to_end(client)
        self.global_bucket = (global_tokens, now)
        if tokens < 1 or global_tokens < 1:
            return max(1, math.ceil(max((1-tokens)*60/settings.per_minute,
                                        (1-global_tokens)*60/settings.global_per_minute)))
        self.clients[client] = (tokens - 1, now)
        self.global_bucket = (global_tokens - 1, now)
        return 0


class AccessMiddleware:
    def __init__(self, app, settings: SecuritySettings):
        self.app = app
        self.settings = settings
        self.budget = RequestBudget(settings)

    def authenticate(self, authorization: str) -> bool:
        credentials = self.settings.credentials
        try:
            scheme, token = authorization.split(' ', 1)
            if scheme.lower() != 'basic' or len(token) > 2048:
                return False
            user, password = base64.b64decode(token, validate=True).decode('utf-8').split(':', 1)
            if len(password.encode('utf-8')) > 1024:
                return False
            derived = password_hash(password, bytes.fromhex(credentials['salt']))
            valid_user = hmac.compare_digest(user.encode('utf-8'), credentials['username'].encode('utf-8'))
            return hmac.compare_digest(derived, bytes.fromhex(credentials['hash'])) and valid_user
        except (ValueError, UnicodeError, binascii.Error):
            return False

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        client = (scope.get('client') or ('unknown', 0))[0]
        retry = self.budget.allow(client)
        if retry:
            response = JSONResponse({'detail': 'Too many requests'}, status_code=429,
                                    headers={'Retry-After': str(retry), 'Cache-Control': 'no-store'})
        elif self.settings.credentials and scope.get('scheme') != 'https':
            # Do not challenge for credentials over cleartext or trust raw forwarded headers.
            response = JSONResponse({'detail': 'HTTPS is required'}, status_code=426,
                                    headers={'Cache-Control': 'no-store'})
        elif self.settings.credentials:
            headers = dict(scope.get('headers', []))
            authorization = headers.get(b'authorization', b'').decode('latin-1')
            if not await run_in_threadpool(self.authenticate, authorization):
                response = JSONResponse({'detail': 'Authentication required'}, status_code=401,
                                        headers={'WWW-Authenticate': 'Basic realm="Cyber RSS", charset="UTF-8"',
                                                 'Cache-Control': 'no-store'})
            else:
                response = None
        else:
            response = None

        async def secure_send(message):
            if message['type'] == 'http.response.start':
                headers = list(message.get('headers', []))
                headers = [(key, value) for key, value in headers if key.lower() != b'x-content-type-options']
                headers.append((b'x-content-type-options', b'nosniff'))
                if self.settings.credentials:
                    headers = [(key, value) for key, value in headers if key.lower() != b'cache-control']
                    headers.append((b'cache-control', b'no-store'))
                if scope.get('scheme') == 'https':
                    headers.append((b'strict-transport-security', b'max-age=31536000'))
                message = {**message, 'headers': headers}
            await send(message)

        if response is not None:
            await response(scope, receive, secure_send)
        else:
            await self.app(scope, receive, secure_send)
