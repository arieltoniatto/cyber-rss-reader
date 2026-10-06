from cli.formatter import article_table


def register(app, services):

    @app.command()
    def search(
        keyword: str,

        category: str | None = None,

        source: str | None = None,

        limit: int = 20,
    ):

        articles = services.search_service.search(
            keywords=[keyword] if keyword else None,
            category=category,
            source=source,
            limit=limit,
        )

        article_table(articles)