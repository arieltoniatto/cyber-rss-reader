from __future__ import annotations

import typer

from rich.console import Console

console = Console()


def register(app, services):

    @app.command()
    def update():

        console.print(
            "[cyan]Updating feeds...[/cyan]"
        )

        services.article_service.update()

        console.print(
            "[green]Update complete.[/green]"
        )