from __future__ import annotations

import typer

from cli.formatter import article_table


def register(app, services):

    @app.command()
    def category(
        name: str,
    ):

        articles = services.article_service.by_category(
            name,
        )

        article_table(articles)