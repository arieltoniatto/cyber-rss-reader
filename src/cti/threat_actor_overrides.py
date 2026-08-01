from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any


JsonObject = dict[str, Any]


class ThreatActorOverrideError(ValueError):
    """
    Raised when local threat actor overrides are invalid.
    """


@dataclass(slots=True, frozen=True)
class AliasAddition:
    """
    Alias locally associated with an ATT&CK group.
    """

    value: str
    sources: tuple[str, ...] = ()
    note: str | None = None


@dataclass(slots=True)
class ParsedActorOverride:
    """
    Validated override associated with one catalog actor.
    """

    actor: JsonObject
    add_aliases: list[AliasAddition]
    remove_aliases: list[str]


def apply_threat_actor_overrides(
    catalog: JsonObject,
    overrides: JsonObject,
    *,
    source_name: str | None = None,
) -> JsonObject:
    """
    Apply locally maintained aliases to a generated ATT&CK catalog.

    The input catalog is not modified. A deep-copied catalog is returned.

    Operations are applied in two phases:

    1. Remove configured aliases.
    2. Add new aliases after validating ownership conflicts.
    """

    result = deepcopy(catalog)

    actors = result.get("actors")

    if not isinstance(actors, list):
        raise ThreatActorOverrideError(
            "Threat actor catalog must contain an actors list."
        )

    if overrides.get("schema_version") != 1:
        raise ThreatActorOverrideError(
            "Unsupported threat actor override schema version. "
            "Expected schema_version 1."
        )

    raw_entries = overrides.get("actors", [])

    if not isinstance(raw_entries, list):
        raise ThreatActorOverrideError(
            "Threat actor overrides must contain an actors list."
        )

    actor_objects = [
        actor
        for actor in actors
        if isinstance(actor, dict)
    ]

    parsed_overrides = _parse_overrides(
        entries=raw_entries,
        actors=actor_objects,
    )

    aliases_removed = _apply_removals(
        parsed_overrides
    )

    aliases_added = _apply_additions(
        actors=actor_objects,
        overrides=parsed_overrides,
    )

    metadata = result.setdefault(
        "metadata",
        {},
    )

    if not isinstance(metadata, dict):
        raise ThreatActorOverrideError(
            "Threat actor catalog metadata must be an object."
        )

    metadata["local_overrides"] = {
        "schema_version": 1,
        "source": source_name,
        "actors_configured": len(parsed_overrides),
        "aliases_added": aliases_added,
        "aliases_removed": aliases_removed,
    }

    return result


def _parse_overrides(
    *,
    entries: list[object],
    actors: list[JsonObject],
) -> list[ParsedActorOverride]:
    parsed: list[ParsedActorOverride] = []
    configured_actors: set[str] = set()

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ThreatActorOverrideError(
                f"Override entry {index} must be an object."
            )

        actor = _resolve_actor(
            entry=entry,
            actors=actors,
            entry_index=index,
        )

        stix_id = _required_string(
            actor,
            "stix_id",
            context="catalog actor",
        )

        if stix_id in configured_actors:
            raise ThreatActorOverrideError(
                f"Actor {stix_id!r} has more than one "
                "override entry."
            )

        configured_actors.add(stix_id)

        add_aliases = _parse_alias_additions(
            entry.get("add_aliases", []),
            entry_index=index,
        )

        remove_aliases = _parse_string_list(
            entry.get("remove_aliases", []),
            context=(
                f"remove_aliases in override entry {index}"
            ),
        )

        _validate_override_operations(
            actor=actor,
            add_aliases=add_aliases,
            remove_aliases=remove_aliases,
        )

        parsed.append(
            ParsedActorOverride(
                actor=actor,
                add_aliases=add_aliases,
                remove_aliases=remove_aliases,
            )
        )

    return parsed


def _resolve_actor(
    *,
    entry: JsonObject,
    actors: list[JsonObject],
    entry_index: int,
) -> JsonObject:
    raw_stix_id = entry.get("stix_id")
    raw_attack_id = entry.get("attack_id")
    raw_name = entry.get("name")

    actor: JsonObject | None = None

    if isinstance(raw_stix_id, str) and raw_stix_id.strip():
        stix_id = raw_stix_id.strip()

        actor = next(
            (
                candidate
                for candidate in actors
                if candidate.get("stix_id") == stix_id
            ),
            None,
        )

        if actor is None:
            raise ThreatActorOverrideError(
                f"Override entry {entry_index} references "
                f"unknown STIX ID {stix_id!r}."
            )

    elif isinstance(raw_attack_id, str) and raw_attack_id.strip():
        attack_id = raw_attack_id.strip()

        matches = [
            candidate
            for candidate in actors
            if candidate.get("attack_id") == attack_id
        ]

        if not matches:
            raise ThreatActorOverrideError(
                f"Override entry {entry_index} references "
                f"unknown ATT&CK ID {attack_id!r}."
            )

        if len(matches) > 1:
            raise ThreatActorOverrideError(
                f"ATT&CK ID {attack_id!r} matches multiple actors. "
                "Use stix_id to identify the actor unambiguously."
            )

        actor = matches[0]

    else:
        raise ThreatActorOverrideError(
            f"Override entry {entry_index} must contain "
            "stix_id or attack_id."
        )

    _validate_actor_identity(
        actor=actor,
        expected_attack_id=raw_attack_id,
        expected_name=raw_name,
        entry_index=entry_index,
    )

    return actor


def _validate_actor_identity(
    *,
    actor: JsonObject,
    expected_attack_id: object,
    expected_name: object,
    entry_index: int,
) -> None:
    if isinstance(expected_attack_id, str):
        actual_attack_id = actor.get("attack_id")

        if actual_attack_id != expected_attack_id.strip():
            raise ThreatActorOverrideError(
                f"Override entry {entry_index} expected ATT&CK ID "
                f"{expected_attack_id!r}, but the selected actor has "
                f"{actual_attack_id!r}."
            )

    if isinstance(expected_name, str):
        actual_name = actor.get("name")

        if (
            not isinstance(actual_name, str)
            or actual_name.casefold()
            != expected_name.strip().casefold()
        ):
            raise ThreatActorOverrideError(
                f"Override entry {entry_index} expected actor "
                f"name {expected_name!r}, but the selected actor "
                f"is {actual_name!r}."
            )


def _parse_alias_additions(
    raw_aliases: object,
    *,
    entry_index: int,
) -> list[AliasAddition]:
    if not isinstance(raw_aliases, list):
        raise ThreatActorOverrideError(
            f"add_aliases in override entry {entry_index} "
            "must be a list."
        )

    additions: list[AliasAddition] = []
    additions_by_key: dict[str, AliasAddition] = {}

    for alias_index, raw_alias in enumerate(raw_aliases):
        addition = _parse_alias_addition(
            raw_alias,
            context=(
                f"add_aliases[{alias_index}] "
                f"in override entry {entry_index}"
            ),
        )

        key = addition.value.casefold()

        existing = additions_by_key.get(key)

        if existing is not None:
            merged_sources = _merge_strings(
                existing.sources,
                addition.sources,
            )

            merged = AliasAddition(
                value=existing.value,
                sources=tuple(merged_sources),
                note=existing.note or addition.note,
            )

            additions_by_key[key] = merged

            for position, item in enumerate(additions):
                if item.value.casefold() == key:
                    additions[position] = merged
                    break

            continue

        additions_by_key[key] = addition
        additions.append(addition)

    return additions


def _parse_alias_addition(
    raw_alias: object,
    *,
    context: str,
) -> AliasAddition:
    if isinstance(raw_alias, str):
        value = _normalize_string(raw_alias)

        if not value:
            raise ThreatActorOverrideError(
                f"{context} contains an empty alias."
            )

        return AliasAddition(
            value=value,
        )

    if not isinstance(raw_alias, dict):
        raise ThreatActorOverrideError(
            f"{context} must be a string or object."
        )

    value = raw_alias.get("value")

    if not isinstance(value, str):
        raise ThreatActorOverrideError(
            f"{context} must contain a string value."
        )

    normalized_value = _normalize_string(value)

    if not normalized_value:
        raise ThreatActorOverrideError(
            f"{context} contains an empty alias."
        )

    sources = _parse_string_list(
        raw_alias.get("sources", []),
        context=f"sources in {context}",
    )

    raw_note = raw_alias.get("note")

    if raw_note is not None and not isinstance(raw_note, str):
        raise ThreatActorOverrideError(
            f"note in {context} must be a string or null."
        )

    note = (
        _normalize_string(raw_note)
        if isinstance(raw_note, str)
        else None
    )

    return AliasAddition(
        value=normalized_value,
        sources=tuple(sources),
        note=note or None,
    )


def _validate_override_operations(
    *,
    actor: JsonObject,
    add_aliases: list[AliasAddition],
    remove_aliases: list[str],
) -> None:
    actor_name = _required_string(
        actor,
        "name",
        context="catalog actor",
    )

    actor_name_key = actor_name.casefold()

    remove_keys = {
        alias.casefold()
        for alias in remove_aliases
    }

    if actor_name_key in remove_keys:
        raise ThreatActorOverrideError(
            f"The canonical actor name {actor_name!r} "
            "cannot be removed."
        )

    added_keys = {
        alias.value.casefold()
        for alias in add_aliases
    }

    conflicting_operations = (
        added_keys & remove_keys
    )

    if conflicting_operations:
        conflicts = ", ".join(
            sorted(conflicting_operations)
        )

        raise ThreatActorOverrideError(
            "The same alias cannot be added and removed "
            f"in one override: {conflicts}."
        )


def _apply_removals(
    overrides: list[ParsedActorOverride],
) -> int:
    removed_count = 0

    for override in overrides:
        remove_keys = {
            alias.casefold()
            for alias in override.remove_aliases
        }

        if not remove_keys:
            continue

        aliases = _actor_aliases(
            override.actor
        )

        retained_aliases = [
            alias
            for alias in aliases
            if alias.casefold() not in remove_keys
        ]

        removed_count += (
            len(aliases)
            - len(retained_aliases)
        )

        override.actor["aliases"] = (
            retained_aliases
        )

        local_aliases = override.actor.get(
            "local_aliases",
            [],
        )

        if isinstance(local_aliases, list):
            override.actor["local_aliases"] = [
                item
                for item in local_aliases
                if not (
                    isinstance(item, dict)
                    and isinstance(
                        item.get("value"),
                        str,
                    )
                    and item["value"].casefold()
                    in remove_keys
                )
            ]

    return removed_count


def _apply_additions(
    *,
    actors: list[JsonObject],
    overrides: list[ParsedActorOverride],
) -> int:
    alias_owners = _build_alias_owner_index(
        actors
    )

    added_count = 0

    for override in overrides:
        actor = override.actor

        actor_stix_id = _required_string(
            actor,
            "stix_id",
            context="catalog actor",
        )

        actor_name = _required_string(
            actor,
            "name",
            context="catalog actor",
        )

        aliases = _actor_aliases(actor)

        alias_keys = {
            alias.casefold()
            for alias in aliases
        }

        local_aliases = actor.setdefault(
            "local_aliases",
            [],
        )

        if not isinstance(local_aliases, list):
            raise ThreatActorOverrideError(
                f"local_aliases for {actor_name!r} "
                "must be a list."
            )

        for addition in override.add_aliases:
            alias_key = addition.value.casefold()

            owners = alias_owners.get(
                alias_key,
                set(),
            )

            foreign_owners = (
                owners - {actor_stix_id}
            )

            if foreign_owners:
                owner_names = _owner_names(
                    actors=actors,
                    owner_ids=foreign_owners,
                )

                raise ThreatActorOverrideError(
                    f"Alias {addition.value!r} for "
                    f"{actor_name!r} is already associated "
                    f"with: {', '.join(owner_names)}."
                )

            if (
                alias_key != actor_name.casefold()
                and alias_key not in alias_keys
            ):
                aliases.append(addition.value)
                alias_keys.add(alias_key)
                added_count += 1

            _upsert_local_alias_metadata(
                local_aliases=local_aliases,
                addition=addition,
            )

            alias_owners.setdefault(
                alias_key,
                set(),
            ).add(actor_stix_id)

        actor["aliases"] = aliases

    return added_count


def _build_alias_owner_index(
    actors: list[JsonObject],
) -> dict[str, set[str]]:
    owners: dict[str, set[str]] = {}

    for actor in actors:
        stix_id = actor.get("stix_id")
        name = actor.get("name")

        if not isinstance(stix_id, str):
            continue

        candidate_aliases = [
            name,
            *_actor_aliases(actor),
        ]

        for candidate in candidate_aliases:
            if not isinstance(candidate, str):
                continue

            normalized = _normalize_string(
                candidate
            )

            if not normalized:
                continue

            owners.setdefault(
                normalized.casefold(),
                set(),
            ).add(stix_id)

    return owners


def _upsert_local_alias_metadata(
    *,
    local_aliases: list[object],
    addition: AliasAddition,
) -> None:
    alias_key = addition.value.casefold()

    existing = next(
        (
            item
            for item in local_aliases
            if (
                isinstance(item, dict)
                and isinstance(
                    item.get("value"),
                    str,
                )
                and item["value"].casefold()
                == alias_key
            )
        ),
        None,
    )

    if existing is None:
        local_aliases.append(
            {
                "value": addition.value,
                "sources": list(
                    addition.sources
                ),
                "note": addition.note,
            }
        )

        return

    existing_sources = existing.get(
        "sources",
        [],
    )

    if not isinstance(existing_sources, list):
        existing_sources = []

    existing["sources"] = _merge_strings(
        existing_sources,
        addition.sources,
    )

    if (
        not existing.get("note")
        and addition.note
    ):
        existing["note"] = addition.note


def _actor_aliases(
    actor: JsonObject,
) -> list[str]:
    raw_aliases = actor.get(
        "aliases",
        [],
    )

    if not isinstance(raw_aliases, list):
        raise ThreatActorOverrideError(
            f"Aliases for actor {actor.get('name')!r} "
            "must be a list."
        )

    return [
        normalized
        for raw_alias in raw_aliases
        if (
            isinstance(raw_alias, str)
            and (
                normalized := _normalize_string(
                    raw_alias
                )
            )
        )
    ]


def _owner_names(
    *,
    actors: list[JsonObject],
    owner_ids: set[str],
) -> list[str]:
    names = [
        str(actor.get("name") or stix_id)
        for actor in actors
        if (
            isinstance(
                stix_id := actor.get("stix_id"),
                str,
            )
            and stix_id in owner_ids
        )
    ]

    return sorted(
        names,
        key=str.casefold,
    )


def _parse_string_list(
    raw_values: object,
    *,
    context: str,
) -> list[str]:
    if not isinstance(raw_values, list):
        raise ThreatActorOverrideError(
            f"{context} must be a list."
        )

    values: list[str] = []
    seen: set[str] = set()

    for raw_value in raw_values:
        if not isinstance(raw_value, str):
            raise ThreatActorOverrideError(
                f"{context} must contain only strings."
            )

        value = _normalize_string(
            raw_value
        )

        if not value:
            continue

        key = value.casefold()

        if key in seen:
            continue

        seen.add(key)
        values.append(value)

    return values


def _merge_strings(
    first: object,
    second: object,
) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()

    for collection in (
        first,
        second,
    ):
        if not isinstance(
            collection,
            (list, tuple),
        ):
            continue

        for value in collection:
            if not isinstance(value, str):
                continue

            normalized = _normalize_string(
                value
            )

            if not normalized:
                continue

            key = normalized.casefold()

            if key in seen:
                continue

            seen.add(key)
            merged.append(normalized)

    return merged


def _required_string(
    obj: JsonObject,
    key: str,
    *,
    context: str,
) -> str:
    value = obj.get(key)

    if not isinstance(value, str):
        raise ThreatActorOverrideError(
            f"{context} is missing string field {key!r}."
        )

    normalized = _normalize_string(value)

    if not normalized:
        raise ThreatActorOverrideError(
            f"{context} contains empty field {key!r}."
        )

    return normalized


def _normalize_string(
    value: str,
) -> str:
    return " ".join(
        value.strip().split()
    )