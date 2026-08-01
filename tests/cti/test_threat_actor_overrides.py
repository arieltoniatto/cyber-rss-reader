from __future__ import annotations

import pytest

from cti.threat_actor_overrides import (
    ThreatActorOverrideError,
    apply_threat_actor_overrides,
)


def create_catalog() -> dict:
    return {
        "metadata": {
            "source": "MITRE ATT&CK",
        },
        "actors": [
            {
                "stix_id": "intrusion-set--actor-one",
                "attack_id": "G0001",
                "name": "Actor One",
                "aliases": [
                    "Official Alias",
                    "Old Alias",
                ],
            },
            {
                "stix_id": "intrusion-set--actor-two",
                "attack_id": "G0002",
                "name": "Actor Two",
                "aliases": [
                    "Second Alias",
                ],
            },
        ],
    }


def test_adds_local_alias() -> None:
    overrides = {
        "schema_version": 1,
        "actors": [
            {
                "stix_id": "intrusion-set--actor-one",
                "attack_id": "G0001",
                "name": "Actor One",
                "add_aliases": [
                    {
                        "value": "Vendor Alias",
                        "sources": [
                            "Vendor CTI",
                        ],
                        "note": "Vendor designation.",
                    }
                ],
            }
        ],
    }

    result = apply_threat_actor_overrides(
        create_catalog(),
        overrides,
        source_name="test-overrides.json",
    )

    actor = result["actors"][0]

    assert actor["aliases"] == [
        "Official Alias",
        "Old Alias",
        "Vendor Alias",
    ]

    assert actor["local_aliases"] == [
        {
            "value": "Vendor Alias",
            "sources": [
                "Vendor CTI",
            ],
            "note": "Vendor designation.",
        }
    ]

    assert result["metadata"][
        "local_overrides"
    ]["aliases_added"] == 1


def test_removes_alias() -> None:
    overrides = {
        "schema_version": 1,
        "actors": [
            {
                "stix_id": "intrusion-set--actor-one",
                "remove_aliases": [
                    "Old Alias",
                ],
            }
        ],
    }

    result = apply_threat_actor_overrides(
        create_catalog(),
        overrides,
    )

    actor = result["actors"][0]

    assert actor["aliases"] == [
        "Official Alias",
    ]

    assert result["metadata"][
        "local_overrides"
    ]["aliases_removed"] == 1


def test_does_not_modify_original_catalog() -> None:
    catalog = create_catalog()

    overrides = {
        "schema_version": 1,
        "actors": [
            {
                "stix_id": "intrusion-set--actor-one",
                "add_aliases": [
                    "Local Alias",
                ],
            }
        ],
    }

    result = apply_threat_actor_overrides(
        catalog,
        overrides,
    )

    assert "Local Alias" not in (
        catalog["actors"][0]["aliases"]
    )

    assert "Local Alias" in (
        result["actors"][0]["aliases"]
    )


def test_rejects_alias_owned_by_another_actor() -> None:
    overrides = {
        "schema_version": 1,
        "actors": [
            {
                "stix_id": "intrusion-set--actor-one",
                "add_aliases": [
                    "Second Alias",
                ],
            }
        ],
    }

    with pytest.raises(
        ThreatActorOverrideError,
        match="already associated",
    ):
        apply_threat_actor_overrides(
            create_catalog(),
            overrides,
        )


def test_rejects_canonical_name_removal() -> None:
    overrides = {
        "schema_version": 1,
        "actors": [
            {
                "stix_id": "intrusion-set--actor-one",
                "remove_aliases": [
                    "Actor One",
                ],
            }
        ],
    }

    with pytest.raises(
        ThreatActorOverrideError,
        match="cannot be removed",
    ):
        apply_threat_actor_overrides(
            create_catalog(),
            overrides,
        )


def test_rejects_name_mismatch() -> None:
    overrides = {
        "schema_version": 1,
        "actors": [
            {
                "stix_id": "intrusion-set--actor-one",
                "name": "Wrong Actor",
                "add_aliases": [
                    "Local Alias",
                ],
            }
        ],
    }

    with pytest.raises(
        ThreatActorOverrideError,
        match="expected actor name",
    ):
        apply_threat_actor_overrides(
            create_catalog(),
            overrides,
        )


def test_can_resolve_unique_attack_id() -> None:
    overrides = {
        "schema_version": 1,
        "actors": [
            {
                "attack_id": "G0001",
                "add_aliases": [
                    "Local Alias",
                ],
            }
        ],
    }

    result = apply_threat_actor_overrides(
        create_catalog(),
        overrides,
    )

    assert "Local Alias" in (
        result["actors"][0]["aliases"]
    )


def test_rejects_duplicate_override_entries() -> None:
    overrides = {
        "schema_version": 1,
        "actors": [
            {
                "stix_id": "intrusion-set--actor-one",
                "add_aliases": [
                    "First Local Alias",
                ],
            },
            {
                "stix_id": "intrusion-set--actor-one",
                "add_aliases": [
                    "Second Local Alias",
                ],
            },
        ],
    }

    with pytest.raises(
        ThreatActorOverrideError,
        match="more than one override entry",
    ):
        apply_threat_actor_overrides(
            create_catalog(),
            overrides,
        )