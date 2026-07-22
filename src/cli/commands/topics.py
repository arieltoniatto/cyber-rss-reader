import asyncio
import typer

from cli.formatter import topic_table


def register(app, services):

    @app.command()
    def topics(
        limit: int = 20,
    ):

        topics = asyncio.run(
                services.topic_service.extract(
            limit=limit,
            )
        )

        topic_table(topics)