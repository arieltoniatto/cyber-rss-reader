from pathlib import Path
import typer

from parser.models import IOCType
from search.models import SearchMatch, SearchOrder, SearchPeriod
from services.export_service import ExportFormat, export_articles


def register(app, services):
    @app.command('export')
    def export(format: ExportFormat = typer.Option(ExportFormat.json, '--format'),
               output: Path | None = typer.Option(None, '--output', '-o'),
               q: str | None = typer.Option(None, '--q'),
               category: str | None = typer.Option(None, '--category'),
               source: str | None = typer.Option(None, '--source'),
               tag: str | None = typer.Option(None, '--tag'),
               ioc: str | None = typer.Option(None, '--ioc'),
               ioc_type: IOCType | None = typer.Option(None, '--ioc-type'),
               threat_actor: str | None = typer.Option(None, '--threat-actor'),
               order: SearchOrder = typer.Option(SearchOrder.newest, '--order'),
               period: SearchPeriod = typer.Option(SearchPeriod.all, '--period'),
               match: SearchMatch = typer.Option(SearchMatch.fuzzy, '--match'),
               fuzzy_threshold: int = typer.Option(80, '--fuzzy-threshold', min=0, max=100),
               limit: int = typer.Option(1000, '--limit', min=1, max=10000),
               offset: int = typer.Option(0, '--offset', min=0, max=1000000)):
        """Export archived articles without collecting. Existing files are never overwritten."""
        try:
            articles = services.search_service.search(keyword=q, category=category, source=source, tag=tag,
                ioc=ioc, ioc_type=ioc_type, threat_actor=threat_actor, newest=order == SearchOrder.newest,
                oldest=order == SearchOrder.oldest, today=period == SearchPeriod.today,
                last_week=period == SearchPeriod.week, match_mode=match, fuzzy_threshold=fuzzy_threshold,
                limit=limit, offset=offset)
            content = export_articles(articles, format)
            if output is None:
                typer.echo(content, nl=False)
            else:
                with output.open('x', encoding='utf-8', newline='') as stream:
                    stream.write(content)
        except (ValueError, OSError) as exc:
            raise typer.BadParameter(str(exc)) from exc
