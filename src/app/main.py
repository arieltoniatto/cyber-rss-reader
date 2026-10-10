from __future__ import annotations

from app.container import ApplicationContainer

from cli.app import create_cli
from cli.dependencies import CLIServices
from config.paths import ensure_runtime_directories
from config.logging import configure_logging


def main() -> None:

    ensure_runtime_directories()

    configure_logging()

    container = ApplicationContainer()

    services = CLIServices(
        article_service=container.article_service,
        search_service=container.search_service,
        topic_service=container.topic_service,
        attack_service=container.attack_service,
    )

    app = create_cli(services)

    app()


if __name__ == "__main__":
    main()