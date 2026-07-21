from __future__ import annotations


class ApplicationServices:
    """
    Container for application services.

    These objects are created by the application's bootstrap
    layer (dependency injection) and passed to the CLI.
    """

    def __init__(
        self,
        article_service,
        search_service,
        topic_service,
    ) -> None:

        self.article_service = article_service
        self.search_service = search_service
        self.topic_service = topic_service