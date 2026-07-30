from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from re import Pattern

from parser.models import Article


_HTML_TAG_PATTERN = re.compile(r"<[^>]+>")


@dataclass(slots=True, frozen=True)
class _CompiledAlias:
    """
    Internal representation of an actor alias.
    """

    canonical_name: str
    alias: str
    pattern: Pattern[str]


class ThreatActorEnricher:
    """
    Detects threat actor names and aliases in article text.

    Detected aliases are converted to the canonical actor name defined
    in the configured threat actor catalog.
    """

    def __init__(
        self,
        catalog_file: Path,
    ) -> None:
        self._catalog_file = catalog_file
        self._aliases = self._load_catalog(
            catalog_file
        )

    @property
    def name(self) -> str:
        return "threat-actor"

    async def enrich(
        self,
        article: Article,
    ) -> Article:
        """
        Return a new Article containing detected threat actors.
        """
        content = self._build_searchable_content(
            article
        )

        detected = self._detect_actors(content)

        threat_actors = self._deduplicate(
            [
                *article.threat_actors,
                *detected,
            ]
        )

        return replace(
            article,
            threat_actors=threat_actors,
        )

    @staticmethod
    def _build_searchable_content(
        article: Article,
    ) -> str:
        parts = (
            article.title,
            article.summary,
        )

        raw_content = " ".join(
            str(part)
            for part in parts
            if part is not None
        )

        decoded_content = html.unescape(
            raw_content
        )

        content_without_html = (
            _HTML_TAG_PATTERN.sub(
                " ",
                decoded_content,
            )
        )

        return " ".join(
            content_without_html.split()
        )

    def _detect_actors(
        self,
        content: str,
    ) -> list[str]:
        matches: list[
            tuple[int, int, str]
        ] = []

        for compiled_alias in self._aliases:
            for match in compiled_alias.pattern.finditer(
                content
            ):
                matches.append(
                    (
                        match.start(),
                        -len(match.group(0)),
                        compiled_alias.canonical_name,
                    )
                )

        # Preserve article appearance order. For matches beginning at
        # the same position, prefer the longest alias.
        matches.sort()

        detected: list[str] = []
        seen: set[str] = set()

        for _, _, canonical_name in matches:
            key = canonical_name.casefold()

            if key in seen:
                continue

            seen.add(key)
            detected.append(canonical_name)

        return detected

    @staticmethod
    def _deduplicate(
        actors: list[str],
    ) -> list[str]:
        unique: list[str] = []
        seen: set[str] = set()

        for actor in actors:
            normalized = " ".join(
                str(actor).strip().split()
            )

            if not normalized:
                continue

            key = normalized.casefold()

            if key in seen:
                continue

            seen.add(key)
            unique.append(normalized)

        return unique

    @classmethod
    def _load_catalog(
        cls,
        catalog_file: Path,
    ) -> tuple[_CompiledAlias, ...]:
        if not catalog_file.exists():
            raise FileNotFoundError(
                "Threat actor catalog not found: "
                f"{catalog_file}"
            )

        try:
            with catalog_file.open(
                encoding="utf-8"
            ) as fp:
                payload = json.load(fp)

        except json.JSONDecodeError as exc:
            raise ValueError(
                "Invalid threat actor catalog JSON: "
                f"{catalog_file}"
            ) from exc

        if not isinstance(payload, list):
            raise ValueError(
                "Threat actor catalog must contain "
                "a JSON list."
            )

        compiled_aliases: list[
            _CompiledAlias
        ] = []

        alias_owners: dict[str, str] = {}

        for index, entry in enumerate(payload):
            if not isinstance(entry, dict):
                raise ValueError(
                    "Threat actor catalog entry "
                    f"{index} must be an object."
                )

            raw_name = entry.get("name")
            raw_aliases = entry.get(
                "aliases",
                [],
            )

            if not isinstance(raw_name, str):
                raise ValueError(
                    "Threat actor catalog entry "
                    f"{index} has an invalid name."
                )

            canonical_name = cls._normalize_name(
                raw_name
            )

            if not canonical_name:
                raise ValueError(
                    "Threat actor catalog entry "
                    f"{index} has an empty name."
                )

            if not isinstance(raw_aliases, list):
                raise ValueError(
                    f"Aliases for {canonical_name!r} "
                    "must be a list."
                )

            aliases = [
                canonical_name,
                *raw_aliases,
            ]

            for raw_alias in aliases:
                if not isinstance(raw_alias, str):
                    raise ValueError(
                        f"Alias for {canonical_name!r} "
                        "must be a string."
                    )

                alias = cls._normalize_name(
                    raw_alias
                )

                if not alias:
                    continue

                alias_key = alias.casefold()

                existing_owner = alias_owners.get(
                    alias_key
                )

                if (
                    existing_owner is not None
                    and existing_owner.casefold()
                    != canonical_name.casefold()
                ):
                    raise ValueError(
                        f"Alias {alias!r} is assigned "
                        "to multiple threat actors: "
                        f"{existing_owner!r} and "
                        f"{canonical_name!r}."
                    )

                if existing_owner is not None:
                    continue

                alias_owners[alias_key] = (
                    canonical_name
                )

                compiled_aliases.append(
                    _CompiledAlias(
                        canonical_name=canonical_name,
                        alias=alias,
                        pattern=cls._compile_alias(
                            alias
                        ),
                    )
                )

        return tuple(compiled_aliases)

    @staticmethod
    def _compile_alias(
        alias: str,
    ) -> Pattern[str]:
        """
        Compile an alias with word-like boundaries.

        This prevents APT29 from matching text such as APT290.
        """
        return re.compile(
            rf"(?<!\w){re.escape(alias)}(?!\w)",
            flags=re.IGNORECASE,
        )

    @staticmethod
    def _normalize_name(
        value: str,
    ) -> str:
        return " ".join(
            value.strip().split()
        )