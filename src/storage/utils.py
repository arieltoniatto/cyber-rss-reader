from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit, urlunsplit
from datetime import datetime

from parser.dates import normalize_datetime

from parser.models import Article, IOC, IOCType, AttackMapping
from dataclasses import asdict


def article_key(article: Article) -> str:
    """
    Stable key used for deduplication.

    URL is preferred because it is typically unique.
    """
    url = article.url.strip()
    if url:
        parts = urlsplit(url)
        return "url:" + urlunsplit((parts.scheme.lower(), parts.netloc.lower(),
                                   parts.path, parts.query, ""))
    identity = json.dumps([article.source, article.title,
                           normalize_datetime(article.published).isoformat()
                           if article.published else None], ensure_ascii=False)
    return "fallback:" + hashlib.sha256(identity.encode()).hexdigest()

def ioc_to_dict(ioc: IOC) -> dict[str, str]:
    """
    Convert an IOC into a JSON-serializable dictionary.
    """
    return {
        "type": ioc.type.value,
        "value": ioc.value,
    }


def ioc_from_dict(data: object) -> IOC | None:
    """
    Convert cached IOC data back into an IOC object.

    Invalid IOC entries are ignored instead of preventing the entire
    article cache from loading.
    """
    if not isinstance(data, dict):
        return None

    raw_type = data.get("type")
    raw_value = data.get("value")

    if not isinstance(raw_type, str):
        return None

    if not isinstance(raw_value, str):
        return None

    try:
        ioc_type = IOCType(raw_type)
    except ValueError:
        return None

    value = raw_value.strip()

    if not value:
        return None

    return IOC(
        type=ioc_type,
        value=value,
    )


def article_to_dict(
    article: Article,
) -> dict[str, object]:
    return {
        "title": article.title,
        "source": article.source,
        "summary": article.summary,
        "url": article.url,
        "category": article.category,
        "author": article.author,
        "published": (
            normalize_datetime(article.published).isoformat()
            if article.published
            else None
        ),
        "tags": list(article.tags),
        "iocs": [
            ioc_to_dict(ioc)
            for ioc in article.iocs
        ],
        "attack": asdict(article.attack) if article.attack else None,
        "cve_ids": list(article.cve_ids),
        "malware": list(article.malware),
        "threat_actors": list(
            article.threat_actors
        ),
    }


def article_from_dict(data: dict) -> Article:
    published = data.get("published")

    if published:
        published = normalize_datetime(datetime.fromisoformat(published))

    raw_tags = data.get("tags", [])

    tags = [
        tag
        for tag in raw_tags
        if isinstance(tag, str)
    ] if isinstance(raw_tags, list) else []

    raw_iocs = data.get("iocs", [])

    iocs = [
        ioc
        for raw_ioc in raw_iocs
        if (ioc := ioc_from_dict(raw_ioc)) is not None
    ] if isinstance(raw_iocs, list) else []

    raw_threat_actors = data.get(
        "threat_actors",
        [],
    )

    raw_malware = data.get("malware", [])
    malware = [value.strip() for value in raw_malware
               if isinstance(value, str) and value.strip()] \
        if isinstance(raw_malware, list) else []

    threat_actors = (
        [
            actor.strip()
            for actor in raw_threat_actors
            if (
                isinstance(actor, str)
                and actor.strip()
            )
        ]
        if isinstance(raw_threat_actors, list)
        else []
    )

    attack = None
    raw_attack = data.get('attack')
    if isinstance(raw_attack, dict) and isinstance(raw_attack.get('catalog_version'), str):
        identifiers = {}
        for key in ('entity_ids', 'technique_ids', 'campaign_ids'):
            values = raw_attack.get(key, [])
            identifiers[key] = sorted({value for value in values if isinstance(value, str)}) if isinstance(values, list) else []
        attack = AttackMapping(catalog_version=raw_attack['catalog_version'], **identifiers)

    return Article(
        title=str(data.get("title") or ""),
        source=str(data.get("source") or ""),
        summary=str(data.get("summary") or ""),
        url=str(data.get("url") or ""),
        category=(
            str(data["category"])
            if data.get("category") is not None
            else None
        ),
        author=(
            str(data["author"])
            if data.get("author") is not None
            else None
        ),
        published=published,
        tags=tags,
        iocs=iocs,
        malware=malware,
        attack=attack,
        cve_ids=sorted({value for value in data.get("cve_ids", []) if isinstance(value, str)})
            if isinstance(data.get("cve_ids", []), list) else [],
        threat_actors=threat_actors,
    )
