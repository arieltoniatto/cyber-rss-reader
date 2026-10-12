"""Preview or explicitly apply article retention; preview is the default."""
import argparse
import json
from pathlib import Path

from config.paths import ARTICLE_DATABASE_FILE
from storage.factory import create_repository,database_url_from_environment
from storage.locks import collector_lock
from storage.maintenance import preview_retention
from storage.retention import RetentionPolicy


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',type=Path,default=ARTICLE_DATABASE_FILE)
    parser.add_argument('--days',type=int,help='Days since last observation; 0 disables age retention.')
    parser.add_argument('--max-articles',type=int,help='Maximum retained articles; 0 disables the size cap.')
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--apply',action='store_true',help='Delete matching articles, preserving feeds and telemetry.')
    group.add_argument('--dry-run',action='store_true',help='Preview without modifying the database (default).')
    args=parser.parse_args()
    try:
        configured=RetentionPolicy.from_environment()
        policy=RetentionPolicy(configured.days if args.days is None else args.days,
                               configured.max_articles if args.max_articles is None else args.max_articles)
        url=database_url_from_environment()
        if args.apply:
            repository=create_repository(database_file=args.database,database_url=url,retention=RetentionPolicy())
            with collector_lock(repository if url else args.database):
                result=repository.prune(policy,dry_run=False)
        else:
            result=preview_retention(policy,database_file=args.database,database_url=url)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result.as_dict(),indent=2,ensure_ascii=False))


if __name__=='__main__':
    main()
