from __future__ import annotations

from pathlib import Path
from typing import Any

import feedparser
import httpx
import pytest
import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
FEEDS_DIRECTORY = PROJECT_ROOT / "src" / "config" / "feeds"

REQUEST_TIMEOUT = httpx.Timeout(
    timeout=20.0,
    connect=10.0,
)

REQUEST_HEADERS = {
    "User-Agent": "CyberRSSReader/1.0",
    "Accept": (
        "application/rss+xml, "
        "application/atom+xml, "
        "application/xml, "
        "text/xml, "
        "*/*;q=0.8"
    ),
}


def load_feed_cases() -> list[pytest.ParameterSet]:
    """Load enabled RSS/Atom feeds from YAML configuration files."""
    if not FEEDS_DIRECTORY.is_dir():
        raise pytest.UsageError(
            f"Feed directory was not found: {FEEDS_DIRECTORY}\n"
            "Update FEEDS_DIRECTORY in tests/integration/test_feed_urls.py."
        )

    yaml_files = sorted(
        [
            *FEEDS_DIRECTORY.glob("*.yaml"),
            *FEEDS_DIRECTORY.glob("*.yml"),
        ]
    )

    if not yaml_files:
        raise pytest.UsageError(
            f"No YAML files were found in: {FEEDS_DIRECTORY}"
        )

    cases: list[pytest.ParameterSet] = []

    for yaml_file in yaml_files:
        with yaml_file.open("r", encoding="utf-8") as file:
            raw: Any = yaml.safe_load(file)

        if not isinstance(raw, dict):
            raise pytest.UsageError(
                f"{yaml_file} must contain a YAML mapping."
            )

        # Ignore structured intelligence files that are not RSS/Atom configs.
        if "sources" in raw and "feeds" not in raw:
            continue

        feeds = raw.get("feeds")

        if not isinstance(feeds, list):
            raise pytest.UsageError(
                f"{yaml_file} must contain a 'feeds' list."
            )

        category = str(raw.get("category", yaml_file.stem))

        for index, feed in enumerate(feeds):
            if not isinstance(feed, dict):
                raise pytest.UsageError(
                    f"{yaml_file}: feeds[{index}] must be a mapping."
                )

            if not feed.get("enabled", True):
                continue

            name = str(feed.get("name", f"feed-{index}"))
            url = feed.get("url")

            if not isinstance(url, str) or not url.strip():
                raise pytest.UsageError(
                    f"{yaml_file}: feed {name!r} has no valid URL."
                )

            cases.append(
                pytest.param(
                    name,
                    category,
                    url,
                    id=f"{category}-{name}",
                )
            )

    if not cases:
        raise pytest.UsageError(
            f"No enabled RSS/Atom feeds were found in {FEEDS_DIRECTORY}."
        )

    return cases


FEED_CASES = load_feed_cases()


@pytest.mark.integration
@pytest.mark.parametrize(
    ("feed_name", "category", "feed_url"),
    FEED_CASES,
)
def test_feed_url_is_available_and_parseable(
    feed_name: str,
    category: str,
    feed_url: str,
) -> None:
    try:
        with httpx.Client(
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
        ) as client:
            response = client.get(feed_url)

    except httpx.RequestError as error:
        pytest.fail(
            f"{feed_name!r} could not be reached.\n"
            f"Category: {category}\n"
            f"URL: {feed_url}\n"
            f"Error: {error}",
            pytrace=False,
        )

    assert response.is_success, (
        f"{feed_name!r} returned HTTP {response.status_code}.\n"
        f"Category: {category}\n"
        f"Configured URL: {feed_url}\n"
        f"Final URL: {response.url}"
    )

    parsed = feedparser.parse(response.content)

    assert parsed.version or parsed.feed or parsed.entries, (
        f"{feed_name!r} returned a response that does not appear to be "
        f"RSS or Atom.\n"
        f"Category: {category}\n"
        f"Configured URL: {feed_url}\n"
        f"Final URL: {response.url}\n"
        f"Content-Type: {response.headers.get('content-type', 'unknown')}\n"
        f"Parser error: {getattr(parsed, 'bozo_exception', 'none')}"
    )