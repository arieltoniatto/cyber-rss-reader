from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from parser.models import Article


@dataclass(slots=True, frozen=True)
class CacheSnapshot:
    """
    Represents one cache snapshot.
    """

    created_at: datetime
    articles: list[Article]
```

---

# storage/interfaces.py

```python
from __future__ import annotations

from abc import ABC, abstractmethod

from parser.models import Article


class ArticleRepository(ABC):
    """
    Abstract storage interface.
    """

    @abstractmethod
    def save(self, articles: list[Article]) -> None:
        ...

    @abstractmethod
    def load(self) -> list[Article]:
        ...

    @abstractmethod
    def clear(self) -> None:
        ...

    @abstractmethod
    def refresh(self, articles: list[Article]) -> None:
        ...

    @abstractmethod
    def is_cache_valid(self) -> bool:
        ...