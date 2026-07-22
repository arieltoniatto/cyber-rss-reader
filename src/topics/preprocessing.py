from __future__ import annotations

import re

from parser.models import Article


_WHITESPACE = re.compile(r"\s+")
_NON_WORD = re.compile(r"[^\w\s-]")


def build_documents(
    articles: list[Article],
) -> list[str]:
    """
    Build one normalized text document per article.
    """

    documents = []

    for article in articles:

        text = " ".join(
            filter(
                None,
                [
                    article.title,
                    article.summary,
                    " ".join(article.tags),
                ],
            )
        )

        text = text.lower()

        text = _NON_WORD.sub(" ", text)

        text = _WHITESPACE.sub(" ", text).strip()

        documents.append(text)

    return documents