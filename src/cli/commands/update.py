import asyncio
from contextlib import nullcontext
from storage.locks import CollectorBusy
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

        lock_factory = getattr(services.article_service, 'collection_lock_factory', None) or nullcontext
        try:
            with lock_factory():
                result = asyncio.run(services.article_service.update(force_refresh=refresh))
        except CollectorBusy as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(1)

        typer.echo()

        typer.echo(f"Feeds downloaded : {result.feeds_downloaded}")
        typer.echo(f"Feeds failed     : {result.feeds_failed}")
        typer.echo(f"Articles parsed  : {result.articles_parsed}")
        typer.echo(f"Articles saved   : {result.articles_saved}")
        if result.articles_pruned:
            typer.echo(f"Articles pruned  : {result.articles_pruned}")

        if result.cache_used:
            typer.echo("Source           : Cache")
        else:
            typer.echo("Source           : Network")

        typer.echo()

        typer.echo("Update complete.")