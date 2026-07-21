from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class SearchQuery:
    """
    Boolean keyword query.

    Example:

    include = {"ransomware", "windows"}
    optional = {"linux"}
    exclude = {"android"}
    """

    include: set[str]
    optional: set[str]
    exclude: set[str]