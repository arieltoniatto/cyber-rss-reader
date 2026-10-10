import typer
from parser.models import IOCType
from cli.entity_filters import nonempty_filter

from cli.formatter import article_table
from search.models import SearchMatch, SearchOrder, SearchPeriod


def register(app, services):
    @app.command()
    def search(
        keyword: str,
        category: str | None = typer.Option(None, "--category", "-c"),
        source: str | None = typer.Option(None, "--source", "-s"),
        tag: str | None = typer.Option(None, "--tag", "-t"),
        ioc: str | None = typer.Option(None, "--ioc", callback=nonempty_filter,
                                       help="Exact extracted IOC value; URLs are case-sensitive."),
        ioc_type: IOCType | None = typer.Option(None, "--ioc-type",
                                              help="Extracted IOC type (value and type must match the same IOC)."),
        threat_actor: str | None = typer.Option(None, "--threat-actor", callback=nonempty_filter,
                                                help="Exact stored actor name, case-insensitive."),
        limit: int = typer.Option(20, "--limit", "-n", min=1),
        offset: int = typer.Option(0, min=0, help="Skip matching results after sorting."),
        order: SearchOrder = typer.Option(SearchOrder.newest, help="Publication order."),
        period: SearchPeriod = typer.Option(SearchPeriod.all, help="Publication period in UTC."),
        match: SearchMatch = typer.Option(SearchMatch.fuzzy, help="Exact substring or approximate matching."),
        fuzzy_threshold: int = typer.Option(80, min=0, max=100, help="Minimum similarity for fuzzy matching."),
    ):
        articles = services.search_service.search(
            keyword=keyword, category=category, source=source, tag=tag,
            ioc=ioc, ioc_type=ioc_type, threat_actor=threat_actor,
            limit=limit, offset=offset, newest=order == SearchOrder.newest,
            oldest=order == SearchOrder.oldest, today=period == SearchPeriod.today,
            last_week=period == SearchPeriod.week, match_mode=match,
            fuzzy_threshold=fuzzy_threshold,
        )
        article_table(articles)
