from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import replace

from parser.models import Article

_CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    flags=re.IGNORECASE,
)

_DEFAULT_KEYWORDS: tuple[str, ...] = (
    "apt",
    "botnet",
    "credential theft",
    "cyber espionage",
    "data breach",
    "ddos",
    "exploit",
    "infostealer",
    "initial access",
    "malware",
    "phishing",
    "ransomware",
    "remote code execution",
    "supply chain",
    "threat actor",
    "vulnerability",
    "zero-day",
)


class TagEnricher:
    """
    Normalizes existing article tags and extracts basic CTI tags from text.
    """

    def __init__(
        self,
        keywords: Iterable[str] | None = None,
    ) -> None:
        configured_keywords = keywords or _DEFAULT_KEYWORDS

        self._keywords = tuple(
            normalized_keyword
            for keyword in configured_keywords
            if (normalized_keyword := self._normalize_tag(keyword))
        )

    @property
    def name(self) -> str:
        return "tag"

    async def enrich(self, article: Article) -> Article:
        """
        Return a new Article containing normalized and extracted tags.

        The original frozen Article instance is not modified.
        """
        content = self._build_searchable_content(article)

        tags: list[str] = []

        tags.extend(article.tags)
        tags.extend(self._extract_keyword_tags(content))
        tags.extend(self._extract_cve_tags(content))

        normalized_tags = self._deduplicate_tags(tags)

        return replace(
            article,
            tags=normalized_tags,
        )

    @staticmethod
    def _build_searchable_content(article: Article) -> str:
        parts = (
            article.title,
            article.summary,
        )

        return " ".join(
            str(part)
            for part in parts
            if part is not None
        )

    def _extract_keyword_tags(self, content: str) -> list[str]:
        normalized_content = content.casefold()

        return [
            keyword
            for keyword in self._keywords
            if keyword.casefold() in normalized_content
        ]

    @staticmethod
    def _extract_cve_tags(content: str) -> list[str]:
        return [
            match.upper()
            for match in _CVE_PATTERN.findall(content)
        ]

    def _deduplicate_tags(
        self,
        tags: Iterable[str],
    ) -> list[str]:
        normalized_tags: list[str] = []
        seen: set[str] = set()

        for tag in tags:
            normalized_tag = self._normalize_tag(tag)

            if not normalized_tag:
                continue

            comparison_key = normalized_tag.casefold()

            if comparison_key in seen:
                continue

            seen.add(comparison_key)
            normalized_tags.append(normalized_tag)

        return sorted(
            normalized_tags,
            key=str.casefold,
        )

    @staticmethod
    def _normalize_tag(tag: str) -> str:
        return " ".join(str(tag).strip().split())