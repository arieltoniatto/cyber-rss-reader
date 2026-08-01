from __future__ import annotations

from cti.attack_stix_catalog import (
    build_threat_actor_catalog,
)


def test_builds_enriched_actor_catalog() -> None:
    group_id = "intrusion-set--group"
    technique_id = "attack-pattern--technique"
    software_id = "malware--software"
    campaign_id = "campaign--campaign"

    bundle = {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "intrusion-set",
                "id": group_id,
                "name": "APT Test",
                "aliases": [
                    "APT Test",
                    "Test Bear",
                ],
                "description": "Test actor.",
                "x_mitre_domains": [
                    "enterprise-attack"
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "G9999",
                        "url": (
                            "https://attack.mitre.org/"
                            "groups/G9999/"
                        ),
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": technique_id,
                "name": "Test Technique",
                "x_mitre_platforms": [
                    "Linux"
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T9999",
                    }
                ],
            },
            {
                "type": "malware",
                "id": software_id,
                "name": "Test Malware",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "S9999",
                    }
                ],
            },
            {
                "type": "campaign",
                "id": campaign_id,
                "name": "Test Campaign",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "C9999",
                    }
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--group-technique",
                "relationship_type": "uses",
                "source_ref": group_id,
                "target_ref": technique_id,
                "description": (
                    "APT Test used Test Technique."
                ),
            },
            {
                "type": "relationship",
                "id": "relationship--group-software",
                "relationship_type": "uses",
                "source_ref": group_id,
                "target_ref": software_id,
            },
            {
                "type": "relationship",
                "id": "relationship--software-technique",
                "relationship_type": "uses",
                "source_ref": software_id,
                "target_ref": technique_id,
            },
            {
                "type": "relationship",
                "id": "relationship--campaign-group",
                "relationship_type": "attributed-to",
                "source_ref": campaign_id,
                "target_ref": group_id,
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--revoked",
                "name": "Revoked Actor",
                "revoked": True,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "G0000",
                    }
                ],
            },
        ],
    }

    catalog = build_threat_actor_catalog(
        bundle,
        attack_version="19.1",
        source_url="https://example.test/attack.json",
    )

    actors = catalog["actors"]

    assert len(actors) == 1

    actor = actors[0]

    assert actor["attack_id"] == "G9999"
    assert actor["name"] == "APT Test"
    assert actor["aliases"] == [
        "Test Bear"
    ]

    assert actor["techniques"][0][
        "attack_id"
    ] == "T9999"

    assert actor["software"][0][
        "attack_id"
    ] == "S9999"

    assert actor["software"][0][
        "techniques"
    ][0]["attack_id"] == "T9999"

    assert actor["campaigns"][0][
        "attack_id"
    ] == "C9999"