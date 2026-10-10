from __future__ import annotations

import html
import hashlib
import json
import re
import logging
from dataclasses import dataclass, replace
from pathlib import Path
from re import Pattern

from parser.models import Article
from cti.misp_threat_actors import merge_actors
from enrichment.text import refang, mask_references


_HTML_TAG_PATTERN = re.compile(r"<[^>]+>")

logger = logging.getLogger(__name__)


@dataclass(slots=True, frozen=True)
class _CompiledAlias:
    """
    Internal representation of an actor alias.
    """

    canonical_name: str
    alias: str
    pattern: Pattern[str]
    requires_context: bool = False


class ThreatActorEnricher:
    """
    Detects threat actor names and aliases in article text.

    Detected aliases are converted to the canonical actor name defined
    in the configured threat actor catalog.
    """

    def __init__(
        self,
        catalog_file: Path,
        *,
        galaxy: dict | None = None,
        overrides_file: Path | None = None,
    ) -> None:
        self._catalog_file = catalog_file
        self._overrides_file = overrides_file
        self._signature = None
        self.reload(galaxy)

    def reload(self, galaxy: dict | None = None) -> None:
        def fingerprint(path):
            stat = path.stat() if path is not None and path.exists() else None
            return (stat.st_mtime_ns, stat.st_size) if stat else None
        signature = (fingerprint(self._catalog_file), fingerprint(self._overrides_file),
                     hashlib.sha256(json.dumps(galaxy, sort_keys=True).encode()).hexdigest())
        if signature == self._signature:
            return
        aliases = self._load_catalog(self._catalog_file, galaxy=galaxy, overrides_file=self._overrides_file)
        self._aliases = aliases
        self._signature = signature

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
            *article.tags,
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
            mask_references(refang(content_without_html)).split()
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
                if compiled_alias.requires_context and not re.search(
                    r'\b(?:threat\s+actors?|(?:hacker|attacker|actor|group|adversary|criminal|APT)s?|grupo|atacante|invasores)\b',
                    content[max(0, match.start()-80):match.start()] + " " + content[match.end():match.end()+80], re.IGNORECASE):
                    continue
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
        *, galaxy: dict | None = None, overrides_file: Path | None = None,
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

        if isinstance(payload, list):
            entries = payload

        elif isinstance(payload, dict):
            entries = payload.get("actors")

            if not isinstance(entries, list):
                raise ValueError(
                    "Threat actor catalog must contain "
                    "an actors list."
                )

        else:
            raise ValueError(
                "Threat actor catalog must contain "
                "a JSON object or list."
            )

        guarded = set()
        if galaxy is not None:
            try:
                overrides = json.loads(overrides_file.read_bytes()) if overrides_file and overrides_file.exists() else None
                entries, guarded = merge_actors(entries, galaxy, overrides)
            except (OSError, ValueError, TypeError, KeyError):
                logger.exception('MISP Galaxy merge failed; preserving MITRE actor detection')

        alias_text_by_key: dict[str, str] = {}

        alias_owners: dict[
            str,
            set[str],
        ] = {}

        for index, entry in enumerate(entries):
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

            for raw_alias in [
                canonical_name,
                *raw_aliases,
            ]:
                if not isinstance(raw_alias, str):
                    continue

                alias = cls._normalize_name(
                    raw_alias
                )

                if not alias:
                    continue

                alias_key = alias.casefold()

                alias_text_by_key.setdefault(
                    alias_key,
                    alias,
                )

                alias_owners.setdefault(
                    alias_key,
                    set(),
                ).add(canonical_name)

        compiled_aliases: list[
            _CompiledAlias
        ] = []

        ambiguous_count = 0
        for alias_key, owners in alias_owners.items():
            alias = alias_text_by_key[alias_key]

            if len(owners) != 1:
                ambiguous_count += 1
                log = logger.debug if galaxy is not None else logger.warning
                log(
                    "Ignoring ambiguous threat actor "
                    "alias %r assigned to: %s",
                    alias,
                    ", ".join(sorted(owners)),
                )

                continue

            canonical_name = next(iter(owners))

            compiled_aliases.append(
                _CompiledAlias(
                    canonical_name=canonical_name,
                    alias=alias,
                    pattern=cls._compile_alias(
                        alias
                    ),
                    requires_context=(canonical_name, alias_key) in guarded,
                )
            )

        if galaxy is not None and ambiguous_count:
            logger.info("Skipped %d ambiguous aliases in the combined MITRE/MISP actor catalog", ambiguous_count)

        # Prefer longer aliases during detection.
        compiled_aliases.sort(
            key=lambda item: (
                -len(item.alias),
                item.alias.casefold(),
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
            rf"(?<![\w.-]){re.escape(alias)}(?![\w-]|\.[\w.-])",
            flags=re.IGNORECASE,
        )

    @staticmethod
    def _normalize_name(
        value: str,
    ) -> str:
        return " ".join(
            value.strip().split()
        )