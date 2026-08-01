from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any


JsonObject = dict[str, Any]


class AttackStixCatalogError(ValueError):
    """
    Raised when an ATT&CK STIX bundle cannot be converted
    into the local threat actor catalog.
    """


def build_threat_actor_catalog(
    bundle: JsonObject,
    *,
    attack_version: str,
    source_url: str,
) -> JsonObject:
    """
    Build the local threat actor catalog from an Enterprise
    ATT&CK STIX 2.1 bundle.

    Revoked and deprecated ATT&CK objects are excluded.
    """

    raw_objects = bundle.get("objects")

    if not isinstance(raw_objects, list):
        raise AttackStixCatalogError(
            "ATT&CK STIX bundle does not contain "
            "an objects list."
        )

    objects = [
        obj
        for obj in raw_objects
        if (
            isinstance(obj, dict)
            and _is_active(obj)
        )
    ]

    objects_by_id = {
        stix_id: obj
        for obj in objects
        if (
            isinstance(
                stix_id := obj.get("id"),
                str,
            )
        )
    }

    uses_by_source: dict[
        str,
        list[JsonObject],
    ] = defaultdict(list)

    campaigns_by_group: dict[
        str,
        list[str],
    ] = defaultdict(list)

    for obj in objects:
        if obj.get("type") != "relationship":
            continue

        source_ref = obj.get("source_ref")
        target_ref = obj.get("target_ref")
        relationship_type = obj.get(
            "relationship_type"
        )

        if not isinstance(source_ref, str):
            continue

        if not isinstance(target_ref, str):
            continue

        if relationship_type == "uses":
            uses_by_source[source_ref].append(obj)

        elif relationship_type == "attributed-to":
            campaigns_by_group[target_ref].append(
                source_ref
            )

    groups = [
        obj
        for obj in objects
        if obj.get("type") == "intrusion-set"
    ]

    actors = [
        _build_actor_entry(
            group=group,
            objects_by_id=objects_by_id,
            uses_by_source=uses_by_source,
            campaigns_by_group=campaigns_by_group,
        )
        for group in groups
    ]

    actors.sort(
        key=lambda actor: str(
            actor.get("name", "")
        ).casefold()
    )

    return {
        "metadata": {
            "source": "MITRE ATT&CK",
            "domain": "enterprise-attack",
            "stix_version": "2.1",
            "attack_version": attack_version,
            "source_url": source_url,
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "actor_count": len(actors),
            "relationship_scope": {
                "techniques": (
                    "Direct group-to-technique "
                    "relationships"
                ),
                "software": (
                    "Direct group-to-software "
                    "relationships"
                ),
                "software_techniques": (
                    "Techniques used by software "
                    "associated with the group"
                ),
                "campaigns": (
                    "Campaigns attributed to the group"
                ),
            },
        },
        "actors": actors,
    }


def _build_actor_entry(
    *,
    group: JsonObject,
    objects_by_id: dict[str, JsonObject],
    uses_by_source: dict[
        str,
        list[JsonObject],
    ],
    campaigns_by_group: dict[
        str,
        list[str],
    ],
) -> JsonObject:
    group_id = _required_string(
        group,
        "id",
    )

    name = _required_string(
        group,
        "name",
    )

    aliases = [
        alias
        for alias in _unique_strings(
            group.get("aliases")
        )
        if alias.casefold() != name.casefold()
    ]

    techniques = _get_related_techniques(
        source_id=group_id,
        objects_by_id=objects_by_id,
        uses_by_source=uses_by_source,
    )

    software = _get_related_software(
        group_id=group_id,
        objects_by_id=objects_by_id,
        uses_by_source=uses_by_source,
    )

    campaigns = _get_related_campaigns(
        group_id=group_id,
        objects_by_id=objects_by_id,
        campaigns_by_group=campaigns_by_group,
    )

    return {
        "attack_id": _attack_id(group),
        "stix_id": group_id,
        "name": name,
        "aliases": aliases,
        "description": _optional_string(
            group.get("description")
        ),
        "created": _optional_string(
            group.get("created")
        ),
        "modified": _optional_string(
            group.get("modified")
        ),
        "first_seen": _optional_string(
            group.get("first_seen")
        ),
        "last_seen": _optional_string(
            group.get("last_seen")
        ),
        "version": _optional_string(
            group.get("x_mitre_version")
        ),
        "attack_spec_version": _optional_string(
            group.get(
                "x_mitre_attack_spec_version"
            )
        ),
        "domains": _unique_strings(
            group.get("x_mitre_domains")
        ),
        "contributors": _unique_strings(
            group.get("x_mitre_contributors")
        ),
        "goals": _unique_strings(
            group.get("goals")
        ),
        "resource_level": _optional_string(
            group.get("resource_level")
        ),
        "primary_motivation": _optional_string(
            group.get("primary_motivation")
        ),
        "secondary_motivations": _unique_strings(
            group.get("secondary_motivations")
        ),
        "url": _attack_url(group),
        "references": _external_references(group),
        "techniques": techniques,
        "software": software,
        "campaigns": campaigns,
    }


def _get_related_techniques(
    *,
    source_id: str,
    objects_by_id: dict[str, JsonObject],
    uses_by_source: dict[
        str,
        list[JsonObject],
    ],
) -> list[JsonObject]:
    techniques: list[JsonObject] = []

    for relationship in uses_by_source.get(
        source_id,
        [],
    ):
        target_ref = relationship.get(
            "target_ref"
        )

        if not isinstance(target_ref, str):
            continue

        target = objects_by_id.get(target_ref)

        if (
            target is None
            or target.get("type") != "attack-pattern"
        ):
            continue

        techniques.append(
            _technique_entry(
                target,
                relationship=relationship,
            )
        )

    return _deduplicate_entries(
        techniques,
        key="stix_id",
    )


def _get_related_software(
    *,
    group_id: str,
    objects_by_id: dict[str, JsonObject],
    uses_by_source: dict[
        str,
        list[JsonObject],
    ],
) -> list[JsonObject]:
    software_entries: list[JsonObject] = []

    for relationship in uses_by_source.get(
        group_id,
        [],
    ):
        target_ref = relationship.get(
            "target_ref"
        )

        if not isinstance(target_ref, str):
            continue

        software = objects_by_id.get(target_ref)

        if software is None:
            continue

        software_type = software.get("type")

        if software_type not in {
            "malware",
            "tool",
        }:
            continue

        software_id = _required_string(
            software,
            "id",
        )

        software_entries.append(
            {
                "attack_id": _attack_id(software),
                "stix_id": software_id,
                "type": software_type,
                "name": _required_string(
                    software,
                    "name",
                ),
                "aliases": [
                    alias
                    for alias in _unique_strings(
                        software.get("x_mitre_aliases")
                    )
                    if alias.casefold()
                    != str(
                        software.get("name", "")
                    ).casefold()
                ],
                "description": _optional_string(
                    software.get("description")
                ),
                "url": _attack_url(software),
                "relationship_description": (
                    _optional_string(
                        relationship.get("description")
                    )
                ),
                "techniques": (
                    _get_related_techniques(
                        source_id=software_id,
                        objects_by_id=objects_by_id,
                        uses_by_source=(
                            uses_by_source
                        ),
                    )
                ),
            }
        )

    return _deduplicate_entries(
        software_entries,
        key="stix_id",
    )


def _get_related_campaigns(
    *,
    group_id: str,
    objects_by_id: dict[str, JsonObject],
    campaigns_by_group: dict[
        str,
        list[str],
    ],
) -> list[JsonObject]:
    campaigns: list[JsonObject] = []

    for campaign_id in campaigns_by_group.get(
        group_id,
        [],
    ):
        campaign = objects_by_id.get(
            campaign_id
        )

        if (
            campaign is None
            or campaign.get("type") != "campaign"
        ):
            continue

        campaigns.append(
            {
                "attack_id": _attack_id(campaign),
                "stix_id": campaign_id,
                "name": _required_string(
                    campaign,
                    "name",
                ),
                "aliases": [
                    alias
                    for alias in _unique_strings(
                        campaign.get("aliases")
                    )
                    if alias.casefold()
                    != str(
                        campaign.get("name", "")
                    ).casefold()
                ],
                "description": _optional_string(
                    campaign.get("description")
                ),
                "first_seen": _optional_string(
                    campaign.get("first_seen")
                ),
                "last_seen": _optional_string(
                    campaign.get("last_seen")
                ),
                "url": _attack_url(campaign),
            }
        )

    return _deduplicate_entries(
        campaigns,
        key="stix_id",
    )


def _technique_entry(
    technique: JsonObject,
    *,
    relationship: JsonObject,
) -> JsonObject:
    return {
        "attack_id": _attack_id(technique),
        "stix_id": _required_string(
            technique,
            "id",
        ),
        "name": _required_string(
            technique,
            "name",
        ),
        "is_subtechnique": bool(
            technique.get(
                "x_mitre_is_subtechnique",
                False,
            )
        ),
        "platforms": _unique_strings(
            technique.get("x_mitre_platforms")
        ),
        "url": _attack_url(technique),
        "relationship_description": (
            _optional_string(
                relationship.get("description")
            )
        ),
    }


def _attack_id(
    obj: JsonObject,
) -> str | None:
    for reference in _raw_external_references(
        obj
    ):
        if (
            reference.get("source_name")
            == "mitre-attack"
        ):
            external_id = reference.get(
                "external_id"
            )

            if isinstance(external_id, str):
                return external_id

    return None


def _attack_url(
    obj: JsonObject,
) -> str | None:
    for reference in _raw_external_references(
        obj
    ):
        if (
            reference.get("source_name")
            == "mitre-attack"
        ):
            url = reference.get("url")

            if isinstance(url, str):
                return url

    return None


def _external_references(
    obj: JsonObject,
) -> list[JsonObject]:
    references: list[JsonObject] = []

    for reference in _raw_external_references(
        obj
    ):
        compact_reference = {
            key: value
            for key in (
                "source_name",
                "external_id",
                "url",
                "description",
            )
            if isinstance(
                value := reference.get(key),
                str,
            )
        }

        if compact_reference:
            references.append(
                compact_reference
            )

    return references


def _raw_external_references(
    obj: JsonObject,
) -> list[JsonObject]:
    raw_references = obj.get(
        "external_references"
    )

    if not isinstance(raw_references, list):
        return []

    return [
        reference
        for reference in raw_references
        if isinstance(reference, dict)
    ]


def _is_active(
    obj: JsonObject,
) -> bool:
    return not (
        bool(obj.get("revoked", False))
        or bool(
            obj.get(
                "x_mitre_deprecated",
                False,
            )
        )
    )


def _unique_strings(
    values: object,
) -> list[str]:
    if not isinstance(values, list):
        return []

    unique: list[str] = []
    seen: set[str] = set()

    for value in values:
        if not isinstance(value, str):
            continue

        normalized = " ".join(
            value.strip().split()
        )

        if not normalized:
            continue

        key = normalized.casefold()

        if key in seen:
            continue

        seen.add(key)
        unique.append(normalized)

    return unique


def _deduplicate_entries(
    entries: Iterable[JsonObject],
    *,
    key: str,
) -> list[JsonObject]:
    unique: list[JsonObject] = []
    seen: set[str] = set()

    for entry in entries:
        value = entry.get(key)

        if not isinstance(value, str):
            continue

        if value in seen:
            continue

        seen.add(value)
        unique.append(entry)

    unique.sort(
        key=lambda entry: (
            str(entry.get("attack_id") or ""),
            str(entry.get("name") or "").casefold(),
        )
    )

    return unique


def _required_string(
    obj: JsonObject,
    key: str,
) -> str:
    value = obj.get(key)

    if not isinstance(value, str):
        raise AttackStixCatalogError(
            f"ATT&CK object is missing "
            f"the required {key!r} property."
        )

    normalized = value.strip()

    if not normalized:
        raise AttackStixCatalogError(
            f"ATT&CK object contains an empty "
            f"{key!r} property."
        )

    return normalized


def _optional_string(
    value: object,
) -> str | None:
    if not isinstance(value, str):
        return None

    normalized = value.strip()

    return normalized or None