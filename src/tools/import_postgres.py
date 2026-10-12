"""Import a SQLite archive into PostgreSQL without altering the original archive."""
import argparse
import json
from pathlib import Path

from storage.factory import create_repository,database_url_from_environment,is_postgres
from storage.postgres_import import import_sqlite,sqlite_snapshot


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sqlite',type=Path,required=True)
    parser.add_argument('--dry-run',action='store_true',help='Validate and count source data without connecting to PostgreSQL.')
    args=parser.parse_args()
    if args.dry_run:
        snapshot,_=sqlite_snapshot(args.sqlite)
        print(json.dumps({'articles':len(snapshot['articles']),'feeds':len(snapshot['feeds']),'dry_run':True}))
        return
    url=database_url_from_environment()
    if not url:
        parser.error('Configure CYBER_RSS_DATABASE_URL or CYBER_RSS_DATABASE_URL_FILE for the destination')
    repo=create_repository(database_url=url)
    if not is_postgres(repo):
        parser.error('The destination must be PostgreSQL')
    print(json.dumps(import_sqlite(repo,args.sqlite)))


if __name__=='__main__':
    main()
