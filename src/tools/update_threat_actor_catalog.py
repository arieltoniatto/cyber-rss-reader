from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import httpx

from config.paths import (
    MITRE_ATTACK_DIRECTORY,
    THREAT_ACTOR_CATALOG_FILE,
)
from cti.attack_stix_catalog import (
    build_threat_actor_catalog,
)


ATTACK_INDEX_URL = (
    "https://raw.githubusercontent.com/"
    "mitre-attack/attack-stix-data/"
    "master/index.json"
)

_ENTERPRISE_COLLECTION_NAME = (
    "Enterprise ATT&CK"
)

_VERSION_PATTERN = re.compile(
    r"^(\d+)\.(\d+)(?:-(.+))?$"
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Download Enterprise ATT&CK STIX 2.1 "
            "and build the threat actor catalog."
        )
    )

    parser.add_argument(
        "--version",
        help=(
            "Specific ATT&CK version, for example "
            "19.1. Defaults to the latest stable "
            "version in the official index."
        ),
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=THREAT_ACTOR_CATALOG_FILE,
        help="Generated threat actor catalog.",
    )

    args = parser.parse_args()

    with httpx.Client(
        timeout=120.0,
        follow_redirects=True,
        headers={
            "User-Agent": (
                "cyber-rss-reader/"
                "threat-actor-catalog-updater"
            )
        },
    ) as client:
        index = _download_json(
            client,
            ATTACK_INDEX_URL,
        )

        release = _select_release(
            index,
            requested_version=args.version,
        )

        version = release["version"]
        source_url = release["url"]

        print(
            "Downloading Enterprise ATT&CK "
            f"{version}..."
        )

        bundle = _download_json(
            client,
            source_url,
        )

    MITRE_ATTACK_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    raw_stix_file = (
        MITRE_ATTACK_DIRECTORY
        / f"enterprise-attack-{version}.json"
    )

    _write_json(
        raw_stix_file,
        bundle,
    )

    catalog = build_threat_actor_catalog(
        bundle,
        attack_version=version,
        source_url=source_url,
    )

    _write_json(
        args.output,
        catalog,
    )

    metadata = catalog["metadata"]

    print(
        f"Generated {args.output} with "
        f"{metadata['actor_count']} actors."
    )

    print(
        f"Raw STIX saved to {raw_stix_file}."
    )


def _download_json(
    client: httpx.Client,
    url: str,
) -> dict[str, Any]:
    response = client.get(url)
    response.raise_for_status()

    payload = response.json()

    if not isinstance(payload, dict):
        raise ValueError(
            f"Expected a JSON object from {url}."
        )

    return payload


def _select_release(
    index: dict[str, Any],
    *,
    requested_version: str | None,
) -> dict[str, str]:
    collections = index.get("collections")

    if not isinstance(collections, list):
        raise ValueError(
            "ATT&CK index does not contain "
            "a collections list."
        )

    enterprise_collection = next(
        (
            collection
            for collection in collections
            if (
                isinstance(collection, dict)
                and collection.get("name")
                == _ENTERPRISE_COLLECTION_NAME
            )
        ),
        None,
    )

    if enterprise_collection is None:
        raise ValueError(
            "Enterprise ATT&CK collection "
            "was not found."
        )

    versions = enterprise_collection.get(
        "versions"
    )

    if not isinstance(versions, list):
        raise ValueError(
            "Enterprise ATT&CK collection "
            "does not contain versions."
        )

    releases = [
        release
        for release in versions
        if (
            isinstance(release, dict)
            and isinstance(
                release.get("version"),
                str,
            )
            and isinstance(
                release.get("url"),
                str,
            )
        )
    ]

    if requested_version is not None:
        release = next(
            (
                item
                for item in releases
                if item["version"]
                == requested_version
            ),
            None,
        )

        if release is None:
            raise ValueError(
                "Enterprise ATT&CK version "
                f"{requested_version!r} "
                "was not found."
            )

        return {
            "version": release["version"],
            "url": release["url"],
        }

    stable_releases = [
        release
        for release in releases
        if _version_key(
            release["version"]
        ) is not None
    ]

    if not stable_releases:
        raise ValueError(
            "No stable Enterprise ATT&CK "
            "release was found."
        )

    latest = max(
        stable_releases,
        key=lambda release: (
            _version_key(
                release["version"]
            )
            or (0, 0)
        ),
    )

    return {
        "version": latest["version"],
        "url": latest["url"],
    }


def _version_key(
    version: str,
) -> tuple[int, int] | None:
    match = _VERSION_PATTERN.fullmatch(
        version
    )

    if match is None:
        return None

    # Ignore beta or prerelease versions.
    if match.group(3) is not None:
        return None

    return (
        int(match.group(1)),
        int(match.group(2)),
    )


def _write_json(
    path: Path,
    payload: object,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_file = path.with_suffix(
        f"{path.suffix}.tmp"
    )

    with temporary_file.open(
        "w",
        encoding="utf-8",
    ) as fp:
        json.dump(
            payload,
            fp,
            indent=2,
            ensure_ascii=False,
        )

        fp.write("\n")

    temporary_file.replace(path)


if __name__ == "__main__":
    main()