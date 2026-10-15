"""Versioned, backend-independent article exports."""
import csv
from datetime import datetime, timezone
from enum import StrEnum
import io
import json

from storage.utils import article_key, article_to_dict


class ExportFormat(StrEnum):
    json = 'json'
    jsonl = 'jsonl'
    csv = 'csv'


MEDIA_TYPES = {'json': 'application/json', 'jsonl': 'application/x-ndjson', 'csv': 'text/csv'}


def record(article):
    return {'id': article_key(article), **article_to_dict(article)}


def spreadsheet_cell(value):
    """Quote formula-like values even when preceded by invisible whitespace."""
    if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')):
        return "'" + value
    return value


def export_articles(articles, format=ExportFormat.json):
    format = ExportFormat(format)
    rows = [record(article) for article in articles]
    if format == ExportFormat.json:
        return json.dumps({'schema_version': 1, 'exported_at': datetime.now(timezone.utc).isoformat(),
                           'count': len(rows), 'articles': rows}, ensure_ascii=False, indent=2) + '\n'
    if format == ExportFormat.jsonl:
        return ''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in rows)
    fields = ['id', 'title', 'source', 'category', 'author', 'published', 'url', 'summary',
              'tags', 'iocs', 'malware', 'threat_actors', 'attack', 'cve_ids']
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: spreadsheet_cell(json.dumps(row.get(key), ensure_ascii=False)
                         if isinstance(row.get(key), (list, dict)) else row.get(key)) for key in fields})
    return stream.getvalue()
