from __future__ import annotations

from app.container import ApplicationContainer

from cli.app import create_cli
from cli.dependencies import CLIServices


def main() -> None:

    container = ApplicationContainer.build()

    services = CLIServices(
        article_service=container.article_service,
        search_service=container.search_service,
        topic_service=container.topic_service,
    )

    app = create_cli(services)

    app()


if __name__ == "__main__":
    main()