import asyncio

import typer

from cli.formatter import article_table

from services.exceptions import InvalidSourceError


def register(app, services):

    @app.command()
    def source(
        name: str | None = typer.Argument(
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
            services.article_service.by_source(
                name,
                limit=limit,
                )
            )
    
        except InvalidSourceError as error:
            typer.echo(error)
            raise typer.Exit(code=1)

        article_table(articles)