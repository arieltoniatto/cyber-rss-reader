import json

import typer
from rich.table import Table
from rich.text import Text
from cli.formatter import console
from cti.cve import normalize_cve


def display(result):
    console.print(Text(f"{result['cve_id']} · {result['status']}"))
    if result['checked_at']:
        console.print(Text(f"Checked: {result['checked_at']}" + (' (stale)' if result['stale'] else '')))
    if result['retry_after']:
        console.print(Text(f"Try again in {result['retry_after']} seconds."))
    record = result['record']
    if not record:
        console.print(Text(result['source_url']))
        return
    console.print(Text(record['state'] + ' · ' + record['title']))
    console.print(Text(record['description']))
    scores = Table('CVSS', 'Score', 'Severity', 'Source', 'Vector')
    for metric in record['cvss']:
        scores.add_row(metric['version'], str(metric['score']), metric['severity'], Text(metric['source']), Text(metric['vector']))
    console.print(scores)
    if not record['cvss']:
        console.print('No CVSS score supplied by the record.')
    console.print(Text('CWE: ' + (', '.join(record['cwes']) or 'not supplied')))
    for product in record['affected']:
        console.print(Text(f"{product['vendor']} · {product['product']} · default: {product['default_status'] or 'not supplied'}"))
        for version in product['versions']:
            console.print(Text(json.dumps(version, ensure_ascii=False)))
    for reference in record['references']:
        console.print(Text(reference))
    console.print(Text(record['source_url']))
    console.print('The record describes a vulnerability; it does not confirm that an article or your computer is affected.')


def register(app, services):
    def service():
        value = getattr(services, 'vulnerability_service', None)
        if value is None:
            raise typer.BadParameter('CVE lookup service is unavailable.')
        return value

    @app.command()
    def cve(identifier: str, offline: bool = typer.Option(False, help='Use only the local cache.'),
            refresh: bool = typer.Option(False, help='Refresh even an unexpired cached record.')):
        """Look up an official CVE record, with a persistent local cache."""
        try:
            identifier = normalize_cve(identifier)
        except ValueError as exc:
            raise typer.BadParameter(str(exc))
        if offline and refresh:
            raise typer.BadParameter('--offline and --refresh cannot be combined.')
        display(service().cached(identifier) if offline else service().lookup(identifier, refresh=refresh))

    @app.command()
    def vulnerabilities(keyword: str, limit: int = typer.Option(5, '--limit', '-n', min=1, max=100)):
        """Inspect mentioned CVEs and cached vulnerability details in archived articles."""
        lookup = service()
        rows = services.search_service.search(keyword=keyword, limit=limit)
        if not rows:
            console.print('No matching articles.')
        for article in rows:
            console.rule(Text(article.title))
            records = lookup.for_article(article)
            if not records:
                console.print('No CVE references found.')
            for record in records:
                display(record)
                if record['status'] == 'not_looked_up' or record['stale']:
                    console.print(Text('Look up with: rss cve ' + record['cve_id']))
