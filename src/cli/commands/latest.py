import asyncio
from datetime import datetime
import typer

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
            limit=limit,
        )
        
        try:
            articles = asyncio.run(
                services.article_service.latest(query)
            )

        except InvalidCategoryError as error:
            typer.echo(error)
            raise typer.Exit(code=1)

        articles.sort(
            key=lambda article: article.published or datetime.min,
            reverse=True,
        )

        article_table(articles)