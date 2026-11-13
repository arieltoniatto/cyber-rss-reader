from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import replace

from parser.models import Article

_CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    flags=re.IGNORECASE,
)

# A keyword must not be glued to other letters ("apt" inside "capture",
# "malware" inside "Malwarebytes"), but digits and punctuation may surround it
# ("APT28", "%20exploited").
_BEFORE = r"(?<![^\W\d_])"
_AFTER = r"(?![^\W\d_])"

# Tags are always the English names below. Patterns run on text with accents
# removed, so Portuguese variants are written without them. English terms are
# matched in every article, since Portuguese articles also use them.
_DEFAULT_RULES: dict[str, tuple[str, ...]] = {
    "apt": (
        # Case-sensitive: lowercase "apt" is an ordinary English adjective.
        r"(?-i:APTs?)(?:[\s-]?\d+)?",
        r"advanced\s+persistent\s+threats?",
        r"ameacas?\s+persistentes?\s+avancadas?",
    ),
    "botnet": (
        r"botnets?",
    ),
    "credential theft": (
        r"credentials?\s+(?:theft|stealing|harvesting)",
        r"stolen\s+credentials",
        r"(?:roubos?|furtos?)\s+de\s+credenciais",
        r"credenciais\s+(?:roubadas|furtadas)",
    ),
    "cyber espionage": (
        r"cyber[\s-]?espionage",
        r"ciberespionagem",
        r"espionagem\s+(?:cibernetica|digital)",
    ),
    "data breach": (
        r"data\s+breach(?:es)?",
        r"vazamentos?\s+de\s+dados",
        r"violac(?:ao|oes)\s+de\s+dados",
    ),
    "ddos": (
        r"ddos(?:ed|ing)?",
        r"distributed\s+denial[\s-]+of[\s-]+service",
        r"negacao\s+de\s+servico\s+distribuid[ao]",
    ),
    "exploit": (
        r"exploit(?:s|ed|ing|ations?|able|ability)?",
        # "Explorar" is too generic on its own; require a nearby flaw.
        r"explora(?:da|das|do|dos|cao|r|m|ndo|ram)\s+(?:\w+\s+){0,2}?(?:vulnerabilidades?|falhas?|brechas?)",
        r"(?:vulnerabilidades?|falhas?|brechas?)\s+(?:\w+\s+){0,3}?explorad[ao]s?",
    ),
    "infostealer": (
        r"info[\s-]?stealers?",
        r"information\s+stealers?",
    ),
    "initial access": (
        r"initial\s+access",
        r"acesso\s+inicial",
    ),
    "malware": (
        r"malwares?",
        r"codigos?\s+maliciosos?",
        r"softwares?\s+maliciosos?",
    ),
    "phishing": (
        r"(?:spear[\s-]?)?phishing",
    ),
    "ransomware": (
        r"ransomwares?",
        # CISA advisory series, usually written "#StopRansomware".
        r"stopransomware",
        r"sequestros?\s+de\s+dados",
    ),
    "remote code execution": (
        r"remote\s+code\s+execution",
        r"(?-i:RCE)s?",
        r"execucao\s+remota\s+de\s+codigo",
    ),
    "supply chain": (
        r"supply[\s-]+chains?",
        r"cadeias?\s+de\s+(?:suprimentos?|fornecimento|abastecimento)",
    ),
    "threat actor": (
        r"threat\s+actors?",
        r"(?:atores?|agentes?)\s+de\s+ameacas?",
    ),
    "vulnerability": (
        r"vulnerabilit(?:y|ies)",
        r"vulnerabilidades?",
    ),
    "zero-day": (
        # "zero days" with a space is also ordinary English ("zero days left").
        r"zero[\s-]?day",
        r"zero-?days",
        r"(?<!\d)0[\s-]?days?",
        r"dias?[\s-]+zero",
    ),
}

KEYWORD_TAGS: frozenset[str] = frozenset(_DEFAULT_RULES)


class TagEnricher:
    """
    Normalizes existing article tags and extracts basic CTI tags from text.
    """

    def __init__(
        self,
        keywords: Iterable[str] | None = None,
        *,
        rules: Mapping[str, Iterable[str]] | None = None,
    ) -> None:
        if rules is None:
            # Plain keywords match as whole words, without inflections.
            rules = (
                {keyword: (r"\s+".join(map(re.escape, keyword.split())),) for keyword in keywords}
                if keywords
                else _DEFAULT_RULES
            )

        self._rules = tuple(
            (
                normalized_tag,
                re.compile(
                    _BEFORE + "(?:" + "|".join(patterns) + ")" + _AFTER,
                    flags=re.IGNORECASE,
                ),
            )
            for tag, patterns in rules.items()
            if (normalized_tag := self._normalize_tag(tag))
        )

    @property
    def name(self) -> str:
        return "tag"

    async def enrich(self, article: Article) -> Article:
        """
        Return a new Article containing normalized and extracted tags.

        The original frozen Article instance is not modified.
        """
        content = self.searchable_content(article)

        tags: list[str] = []

        tags.extend(article.tags)
        tags.extend(self.keyword_tags(content))
        tags.extend(self._extract_cve_tags(content))

        normalized_tags = self.deduplicate_tags(tags)

        return replace(
            article,
            tags=normalized_tags,
        )

    @staticmethod
    def searchable_content(article: Article) -> str:
        parts = (
            article.title,
            article.summary,
        )

        return " ".join(
            str(part)
            for part in parts
            if part is not None
        )

    def keyword_tags(self, content: str) -> list[str]:
        normalized_content = self._strip_accents(content)

        return [
            tag
            for tag, pattern in self._rules
            if pattern.search(normalized_content)
        ]

    @staticmethod
    def _strip_accents(content: str) -> str:
        decomposed = unicodedata.normalize("NFKD", content)

        return "".join(
            character
            for character in decomposed
            if not unicodedata.combining(character)
        )

    @staticmethod
    def _extract_cve_tags(content: str) -> list[str]:
        return [
            match.upper()
            for match in _CVE_PATTERN.findall(content)
        ]

    def deduplicate_tags(
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
