from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"
    ASN = "asn"


@dataclass(slots=True, frozen=True)
class IOC:
    """
    Observable or indicator extracted from an article.
    """

    type: IOCType
    value: str


@dataclass(slots=True, frozen=True)
class AttackMapping:
    """Article references pinned to a catalog release; relationships resolve on demand."""
    catalog_version: str
    entity_ids: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    campaign_ids: list[str] = field(default_factory=list)


@dataclass(slots=True, frozen=True)
class Article:
    """
    Unified article model used throughout the application,
    regardless of the original RSS/Atom feed format.
    """

    title: str
    source: str
    summary: str
    url: str

    category: str | None = None
    author: str | None = None
    published: datetime | None = None

    tags: list[str] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    malware: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)

    attack: AttackMapping | None = None
