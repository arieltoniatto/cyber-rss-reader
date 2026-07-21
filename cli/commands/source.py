from __future__ import annotations

import typer

from cli.formatter import article_table


def register(app, services):

    @app.command()
    def source(
        name: str,
    ):

        articles = services.article_service.by_source(
            name,
        )

        article_table(articles)