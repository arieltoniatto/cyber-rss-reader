import asyncio

from cli.formatter import article_table


def register(app, services):

    @app.command()
    def source(
        name: str,
    ):

        articles = asyncio.run(
                services.article_service.by_source(
            name,
            )
        )

        article_table(articles)