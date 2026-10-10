import typer
from rich.text import Text
from rich.table import Table
from cli.formatter import console


def register(app, services):
    @app.command()
    def attack(keyword: str, limit: int = typer.Option(5, '--limit', '-n', min=1),
               max_relations: int = typer.Option(20, min=1, help='Maximum catalog relations displayed per article.')):
        """Inspect article references and related ATT&CK catalog context."""
        service = getattr(services, 'attack_service', None)
        if service is None:
            raise typer.BadParameter('ATT&CK mapping service is unavailable.')
        rows = service.search(keyword, limit=limit)
        if not rows:
            console.print('No matching articles.')
        for article, mapping in rows:
            console.rule(Text(article.title))
            console.print(Text(f"ATT&CK {mapping['catalog_version'] or '-'} · {mapping['status']}"))
            if mapping['status'] != 'ok':
                if article.attack:
                    console.print(Text('Stored references: ' + ', '.join(article.attack.entity_ids)))
                continue
            for basis, title in [('article', 'Article references'), ('catalog', 'Related catalog context')]:
                table = Table(title=title)
                table.add_column('ID'); table.add_column('Name'); table.add_column('Type')
                for kind in ('techniques', 'campaigns'):
                    for node in mapping[kind]:
                        if node['basis'] == basis:
                            table.add_row(Text(node['id']), Text(node['name']), kind)
                console.print(table)
            relations = Table(title='MITRE catalog relationships (not article assertions)')
            for label in ('Source', 'Relationship', 'Target'):
                relations.add_column(label)
            for edge in mapping['relationships'][:max_relations]:
                relations.add_row(Text(edge['source_id'] + ' ' + edge['source']['name']), edge['type'],
                                  Text(edge['target_id'] + ' ' + edge['target']['name']))
            console.print(relations)
            if len(mapping['relationships']) > max_relations:
                console.print(Text(f"Showing {max_relations} of {len(mapping['relationships'])} relations; use --max-relations to expand."))
