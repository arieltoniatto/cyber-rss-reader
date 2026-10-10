from __future__ import annotations

from parser.models import Article, IOCType
from search.engine import SearchEngine
from search.models import SearchFilters, SearchMatch
from search.query import SearchQuery
from storage.interfaces import ArticleRepository


class SearchService:
    """
    Application service responsible for searching cached articles.

    This service:
        - loads cached articles
        - builds SearchQuery objects
        - builds SearchFilters
        - delegates searching to SearchEngine
    """

    def __init__(
        self,
        *,
        repository: ArticleRepository,
        engine: SearchEngine,
    ) -> None:

        self._repository = repository
        self._engine = engine

    def search(
        self,
        *,
        keyword: str | None = None,
        keywords: list[str] | None = None,
        any_keywords: list[str] | None = None,
        exclude: list[str] | None = None,
        category: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        today: bool = False,
        last_week: bool = False,
        newest: bool | None = None,
        oldest: bool = False,
        limit: int = 20,
        fuzzy_threshold: int = 80,
        offset: int = 0,
        match_mode: SearchMatch = SearchMatch.fuzzy,
        ioc: str | None = None,
        ioc_type: IOCType | None = None,
        threat_actor: str | None = None,
    ) -> list[Article]:
        """
        Search cached articles.

        include      -> AND

        any_keywords -> OR

        exclude      -> NOT
        """

        if keyword:
            keywords = [keyword, *(keywords or [])]

        query = SearchQuery(
            keyword=set(keywords or []),
            any_terms=set(any_keywords or []),
            title=set(),
            summary=set(),
            author=set(),
            source={source} if source else set(),
            category={category} if category else set(),
            tags=set(),
            exclude=set(exclude or []),
        )

        filters = SearchFilters(
            tag=tag,
            ioc=ioc, ioc_type=ioc_type, threat_actor=threat_actor,
            today=today,
            last_week=last_week,
            category=category,
            source=source,
            newest=not oldest if newest is None else newest,
            oldest=oldest,
            limit=limit,
            fuzzy_threshold=fuzzy_threshold,
            offset=offset,
            match_mode=match_mode,
        )

        return self._engine.search(
            self._repository.load(),
            query,
            filters,
        )
