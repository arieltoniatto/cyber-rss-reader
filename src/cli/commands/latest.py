import asyncio
from datetime import datetime

import typer

from cli.formatter import article_table

from services.exceptions import InvalidCategoryError


def register(app, services):

    @app.command()
    def latest(
        category: str | None = typer.Argument(
            None,
            help="Category to filter by.",
        ),
        limit: int = typer.Option(
            20,
            min=1,
        ),
    ):
        try:
            articles = asyncio.run(
                services.article_service.latest(
                    category=category,
                    limit=limit,
                )
            )

        except InvalidCategoryError as error:
            typer.echo(error)
            raise typer.Exit(code=1)

        articles.sort(
            key=lambda article: article.published or datetime.min,
            reverse=True,
        )

        article_table(articles)