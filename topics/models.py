from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class Topic:
    """
    Represents one extracted topic.
    """

    topic: str
    score: float
    frequency: int