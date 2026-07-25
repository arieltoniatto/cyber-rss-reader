from pathlib import Path

import yaml
from pydantic import ValidationError

from .exceptions import (
    DuplicateFeedError,
    FeedDirectoryNotFound,
    InvalidConfiguration,
)
from .models import FeedCategory, FeedConfiguration


class ConfigLoader:
    """
    Loads every YAML file inside the feeds directory.
    """

    def __init__(self, feeds_directory: Path):
        self.feeds_directory = feeds_directory

    def load(self) -> FeedConfiguration:
        if not self.feeds_directory.exists():
            raise FeedDirectoryNotFound(
                f"Directory not found: {self.feeds_directory}"
            )

        if not self.feeds_directory.is_dir():
            raise FeedDirectoryNotFound(
                f"{self.feeds_directory} is not a directory."
            )

        categories: list[FeedCategory] = []

        for file in sorted(self.feeds_directory.glob("*.yaml")):
            categories.append(self._load_category(file))

        self._validate_duplicates(categories)

        return FeedConfiguration(
            source_directory=self.feeds_directory,
            categories=categories,
        )

    def _load_category(self, file: Path) -> FeedCategory:
        try:
            with file.open("r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
 
            category = FeedCategory.model_validate(raw)

            category.feeds = [
                feed.model_copy(
                    update={
                        "category": category.category
                    }
                )
                for feed in category.feeds
                if feed.enabled
            ]

            
            return category

        except ValidationError as exc:
            raise InvalidConfiguration(
                f"Validation error in {file.name}\n{exc}"
            ) from exc

        except yaml.YAMLError as exc:
            raise InvalidConfiguration(
                f"Invalid YAML in {file.name}"
            ) from exc

    @staticmethod
    def _validate_duplicates(categories: list[FeedCategory]) -> None:
        names: set[str] = set()
        urls: set[str] = set()

        for category in categories:
            for feed in category.feeds:

                if feed.name in names:
                    raise DuplicateFeedError(
                        f"Duplicate feed name: {feed.name}"
                    )

                if str(feed.url) in urls:
                    raise DuplicateFeedError(
                        f"Duplicate feed URL: {feed.url}"
                    )

                names.add(feed.name)
                urls.add(str(feed.url))