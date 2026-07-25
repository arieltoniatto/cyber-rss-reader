from __future__ import annotations
import asyncio

import typer

from cli.formatter import article_table

from services.exceptions import InvalidCategoryError


def register(app, services):

    @app.command()
    def category(
        name: str,
        limit: int = typer.Option(
            20,
            min=1,
        ),
    ):

        try:
            articles = asyncio.run(
                services.article_service.by_category(
                    name,
                    limit=limit,
                )
            )

        except InvalidCategoryError as error:
            typer.echo(error)
            raise typer.Exit(code=1)

        article_table(articles)