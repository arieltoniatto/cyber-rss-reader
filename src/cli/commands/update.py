import asyncio
import typer

from cli.dependencies import CLIServices


def register(app: typer.Typer, services: CLIServices) -> None:

    @app.command()
    def update(
        refresh: bool = typer.Option(
            False,
            "--refresh",
            "-r",
            help="Ignore cache and download all feeds again.",
        ),
    ) -> None:
        typer.echo("Updating feeds...")

        result = asyncio.run(
            services.article_service.update(
                force_refresh=refresh,
            )
        )

        typer.echo()

        typer.echo(f"Feeds downloaded : {result.feeds_downloaded}")
        typer.echo(f"Articles parsed  : {result.articles_parsed}")
        typer.echo(f"Articles saved   : {result.articles_saved}")

        if result.cache_used:
            typer.echo("Source           : Cache")
        else:
            typer.echo("Source           : Network")

        typer.echo()

        typer.echo("Update complete.")