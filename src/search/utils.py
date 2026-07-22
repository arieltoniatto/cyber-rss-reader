from __future__ import annotations

from rapidfuzz import fuzz

from parser.models import Article


from parser.models import Article


def searchable_fields(article: Article) -> dict[str, str]:
    """
    Return every searchable field individually.
    """

    return {
        "keyword": " ".join(
            filter(
                None,
                [
                    article.title,
                    article.summary,
                    article.author,
                    article.source,
                    article.category,
                    " ".join(article.tags),
                ],
            )
        ),

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