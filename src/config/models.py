from pathlib import Path
from typing import List

from pydantic import BaseModel, Field, HttpUrl, ConfigDict


class Feed(BaseModel):
    """Represents a single RSS feed definition."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    url: HttpUrl
    enabled: bool = True
    description: str | None = None
    category: str | None = None


class FeedCategory(BaseModel):
    """Represents one YAML configuration file."""

    model_config = ConfigDict(extra="forbid")

    category: str
    feeds: List[Feed]


class FeedConfiguration(BaseModel):
    """Represents the complete configuration."""

    model_config = ConfigDict(extra="forbid")

    source_directory: Path
    categories: List[FeedCategory]