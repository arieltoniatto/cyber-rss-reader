from __future__ import annotations

from rapidfuzz import fuzz

from parser.models import Article


def searchable_text(article: Article) -> dict[str, str]:

    return {
        "title": article.title or "",
        "summary": article.summary or "",
        "author": article.author or "",
        "source": article.source or "",
        "category": article.category or "",
        "tags": " ".join(article.tags),
    }


def fuzzy_contains(
    text: str,
    keyword: str,
    threshold: int,
) -> bool:

    text = text.lower()
    keyword = keyword.lower()

    if keyword in text:
        return True

    score = fuzz.partial_ratio(keyword, text)

    return score >= threshold