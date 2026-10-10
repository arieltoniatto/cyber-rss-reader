import asyncio
from datetime import datetime
import typer
from parser.models import IOCType
from cli.entity_filters import nonempty_filter

from cli.formatter import article_table

from services.exceptions import InvalidCategoryError
from services.models import LatestQuery


def register(app, services):

    @app.command()
    def latest(
        category: str | None = typer.Option(
            None,
            "--category",
            "-c",
            help="Filter by category.",
        ),
        source: str | None = typer.Option(
            None,
            "--source",
            "-s",
            help="Filter by source.",
        ),
        tag: str | None = typer.Option(
            None,
            "--tag",
            "-t",
            help="Filter articles by tag.",
        ),
        ioc: str | None = typer.Option(None, "--ioc", callback=nonempty_filter,
                                       help="Exact extracted IOC value; URLs are case-sensitive."),
        ioc_type: IOCType | None = typer.Option(None, "--ioc-type",
                                              help="Extracted IOC type (value and type must match the same IOC)."),
        threat_actor: str | None = typer.Option(None, "--threat-actor", callback=nonempty_filter,
                                                help="Exact stored actor name, case-insensitive."),
        limit: int = typer.Option(
            20,
            "--limit",
            "-n",
            min=1,
        ),
    ):

        query = LatestQuery(
            category=category,
            source=source,
            tag=tag,
            ioc=ioc, ioc_type=ioc_type, threat_actor=threat_actor,
            limit=limit,
        )

        try:
            articles = asyncio.run(
                services.article_service.latest(query)
            )

        except InvalidCategoryError as error:
            typer.echo(error)
            raise typer.Exit(code=1)

        article_table(articles)
