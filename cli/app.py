from __future__ import annotations

import typer

from .commands.category import register as category_command
from .commands.latest import register as latest_command
from .commands.search import register as search_command
from .commands.source import register as source_command
from .commands.topics import register as topics_command
from .commands.update import register as update_command
from .dependencies import ApplicationServices


def create_cli(
    services: ApplicationServices,
) -> typer.Typer:

    app = typer.Typer(
        name="rss",
        help="Cybersecurity RSS Reader",
        no_args_is_help=True,
    )

    update_command(app, services)
    latest_command(app, services)
    search_command(app, services)
    topics_command(app, services)
    source_command(app, services)
    category_command(app, services)

    return app