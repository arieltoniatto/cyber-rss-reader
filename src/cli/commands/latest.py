import asyncio
import typer

from cli.formatter import article_table


def register(app, services):

    @app.command()
    def latest(
        limit: int = typer.Option(
            20,
            min=1,
        )
    ):

        articles = asyncio.run(
                services.article_service.latest(
                limit=limit,
            )
        )

        article_table(articles)