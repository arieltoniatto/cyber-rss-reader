"""Explicit archive retention: disabled by default, by last observation and/or size."""
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import json
import os


@dataclass(frozen=True)
class RetentionPolicy:
    days: int = 0
    max_articles: int = 0

    def __post_init__(self):
        if type(self.days) is not int or not 0 <= self.days <= 36500:
            raise ValueError('Retention days must be an integer between 0 and 36500')
        if type(self.max_articles) is not int or not 0 <= self.max_articles <= 10000000:
            raise ValueError('Retention maximum must be an integer between 0 and 10000000')

    @property
    def enabled(self):
        return bool(self.days or self.max_articles)

    @classmethod
    def from_environment(cls):
        try:
            return cls(int(os.environ.get('CYBER_RSS_RETENTION_DAYS','0')),
                       int(os.environ.get('CYBER_RSS_RETENTION_MAX_ARTICLES','0')))
        except ValueError as exc:
            raise ValueError('Invalid CYBER_RSS_RETENTION_DAYS or CYBER_RSS_RETENTION_MAX_ARTICLES') from exc


@dataclass(frozen=True)
class RetentionResult:
    policy: RetentionPolicy
    dry_run: bool
    cutoff: str | None
    before: int
    expired: int
    over_limit: int
    remaining: int

    @property
    def deleted(self):
        return 0 if self.dry_run else self.expired + self.over_limit

    def as_dict(self):
        return {**asdict(self),'enabled':self.policy.enabled,'would_delete':self.expired+self.over_limit,'deleted':self.deleted}


def prune(connection, policy, *, backend, dry_run=False, now=None):
    now = datetime.now(timezone.utc) if now is None else now.astimezone(timezone.utc)
    postgres = backend == 'postgresql'
    table = 'cyber_rss.articles' if postgres else 'articles'
    placeholder = '%s' if postgres else '?'
    if postgres and not dry_run:
        connection.execute('LOCK TABLE cyber_rss.articles IN SHARE ROW EXCLUSIVE MODE')
    before = connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
    cutoff = now - timedelta(days=policy.days) if policy.days else None
    condition = ('last_seen < %s' if postgres else 'julianday(last_seen) < julianday(?)') if cutoff else 'FALSE'
    params = [cutoff if postgres else cutoff.isoformat()] if cutoff else []
    expired = connection.execute(f'SELECT COUNT(*) FROM {table} WHERE {condition}',params).fetchone()[0] if cutoff else 0
    over_limit = max(0,before-expired-policy.max_articles) if policy.max_articles else 0
    result = RetentionResult(policy,dry_run,cutoff.isoformat() if cutoff else None,before,expired,over_limit,before-expired-over_limit)
    if dry_run or not policy.enabled:
        return result
    if expired:
        connection.execute(f'DELETE FROM {table} WHERE {condition}',params)
    if over_limit:
        key = 'key_hash' if postgres else 'id'
        ordering = 'last_seen DESC,published DESC NULLS LAST,id COLLATE "C"' if postgres else 'julianday(last_seen) DESC,published DESC,id'
        paging = 'OFFSET %s' if postgres else 'LIMIT -1 OFFSET ?'
        connection.execute(f'DELETE FROM {table} WHERE {key} IN (SELECT {key} FROM {table} ORDER BY {ordering} {paging})',[policy.max_articles])
    audit = json.dumps({**result.as_dict(),'applied_at':now.isoformat()},ensure_ascii=False)
    metadata = 'cyber_rss.metadata' if postgres else 'metadata'
    connection.execute(f'INSERT INTO {metadata} (key,value) VALUES ({placeholder},{placeholder}) ON CONFLICT(key) DO UPDATE SET value=excluded.value', ['last_retention',audit])
    return result
