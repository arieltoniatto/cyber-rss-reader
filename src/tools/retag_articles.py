"""Preview or explicitly apply the current tag rules to stored articles; preview is the default."""
import argparse
from collections import Counter
from contextlib import closing
from dataclasses import replace
import json
from pathlib import Path
import sqlite3

from config.paths import ARTICLE_DATABASE_FILE
from enrichment.tag_enricher import KEYWORD_TAGS, TagEnricher
from parser.models import Article
from storage.factory import create_repository, database_url_from_environment
from storage.locks import collector_lock
from storage.postgres_storage import driver
from storage.retention import RetentionPolicy
from storage.utils import article_from_dict


def retag(article: Article, enricher: TagEnricher) -> Article:
    """Replace keyword tags from the old substring rule with the current rules.

    Stored tags mix feed tags and extracted ones. A keyword tag is removed only
    when the old rule (the tag name anywhere in title + summary) explains it and
    the current rules do not; otherwise it came from the feed and is kept.
    """
    content = enricher.searchable_content(article)
    folded = content.casefold()
    current = enricher.keyword_tags(content)
    kept = [tag for tag in article.tags
            if not (tag.casefold() in KEYWORD_TAGS and tag.casefold() not in current
                    and tag.casefold() in folded)]
    return replace(article, tags=enricher.deduplicate_tags([*kept, *current]))


def _load_read_only(database_file, database_url):
    """Read articles without initializing or migrating the database."""
    if database_url:
        psycopg, _ = driver()
        with psycopg.connect(database_url, connect_timeout=10) as connection:
            connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            if connection.execute("SELECT to_regclass('cyber_rss.articles')").fetchone()[0] is None:
                return []
            return [article_from_dict(row[0]) for row in
                    connection.execute('SELECT payload FROM cyber_rss.articles')]
    path = Path(database_file)
    if not path.exists():
        return []
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=30)) as connection:
        if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='articles'").fetchone() is None:
            return []
        return [article_from_dict(json.loads(row[0])) for row in
                connection.execute('SELECT payload FROM articles')]


def _report(articles, changed, *, applied, examples):
    removed, added = Counter(), Counter()
    samples = []
    for before, after in changed:
        old = {tag.casefold() for tag in before.tags}
        new = {tag.casefold() for tag in after.tags}
        removed.update(old - new)
        added.update(new - old)
        if len(samples) < examples:
            samples.append({'title': before.title, 'removed': sorted(old - new), 'added': sorted(new - old)})
    return {'applied': applied, 'articles': len(articles), 'changed': len(changed),
            'removed': dict(removed.most_common()), 'added': dict(added.most_common()), 'examples': samples}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, default=ARTICLE_DATABASE_FILE)
    parser.add_argument('--examples', type=int, default=10, help='Changed articles to list in the report.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--apply', action='store_true', help='Rewrite the tags of changed articles.')
    group.add_argument('--dry-run', action='store_true', help='Preview without modifying the database (default).')
    args = parser.parse_args()
    enricher = TagEnricher()
    url = database_url_from_environment()

    def changes(articles):
        pairs = ((article, retag(article, enricher)) for article in articles)
        return [(before, after) for before, after in pairs if before.tags != after.tags]

    try:
        if args.apply:
            # Retention is disabled here: rewriting tags must never prune articles.
            repository = create_repository(database_file=args.database, database_url=url, retention=RetentionPolicy())
            with collector_lock(repository if url else args.database):
                articles = repository.load()
                changed = changes(articles)
                repository.update_tags([after for _, after in changed])
        else:
            articles = _load_read_only(args.database, url)
            changed = changes(articles)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(_report(articles, changed, applied=args.apply, examples=args.examples),
                     indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
