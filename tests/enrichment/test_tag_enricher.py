from __future__ import annotations

import pytest

from enrichment.tag_enricher import TagEnricher
from parser.models import Article


def create_article(
    *,
    title: str,
    summary: str = "",
    tags: list[str] | None = None,
) -> Article:
    return Article(
        title=title,
        source="Test Source",
        summary=summary,
        url="https://example.com/article",
        category="news",
        author=None,
        published=None,
        tags=list(tags or []),
    )


@pytest.mark.asyncio
async def test_preserves_existing_tags() -> None:
    enricher = TagEnricher()

    article = create_article(
        title="Security update",
        tags=[
            "Microsoft",
            "Windows",
        ],
    )

    result = await enricher.enrich(article)

    assert "Microsoft" in result.tags
    assert "Windows" in result.tags


@pytest.mark.asyncio
async def test_extracts_cti_keywords() -> None:
    enricher = TagEnricher()

    article = create_article(
        title="Ransomware attack causes data breach",
        summary="The threat actor used phishing for initial access.",
    )

    result = await enricher.enrich(article)

    assert "ransomware" in result.tags
    assert "data breach" in result.tags
    assert "threat actor" in result.tags
    assert "phishing" in result.tags
    assert "initial access" in result.tags


@pytest.mark.asyncio
async def test_extracts_and_normalizes_cves() -> None:
    enricher = TagEnricher()

    article = create_article(
        title="Exploit published for cve-2026-12345",
        summary="The issue is tracked as CVE-2026-9999.",
    )

    result = await enricher.enrich(article)

    assert "CVE-2026-12345" in result.tags
    assert "CVE-2026-9999" in result.tags


@pytest.mark.asyncio
async def test_removes_duplicate_tags_case_insensitively() -> None:
    enricher = TagEnricher()

    article = create_article(
        title="Ransomware incident",
        tags=[
            "Ransomware",
            " ransomware ",
            "RANSOMWARE",
        ],
    )

    result = await enricher.enrich(article)

    ransomware_tags = [
        tag
        for tag in result.tags
        if tag.casefold() == "ransomware"
    ]

    assert ransomware_tags == ["Ransomware"]


@pytest.mark.asyncio
async def test_does_not_modify_original_article() -> None:
    enricher = TagEnricher()

    article = create_article(
        title="Ransomware incident",
        tags=[],
    )

    result = await enricher.enrich(article)

    assert article.tags == []
    assert result.tags == ["ransomware"]
    assert result is not article


@pytest.mark.asyncio
async def test_creates_a_separate_tags_list() -> None:
    enricher = TagEnricher()

    article = create_article(
        title="Ransomware incident",
        tags=["existing"],
    )

    result = await enricher.enrich(article)

    assert result.tags is not article.tags