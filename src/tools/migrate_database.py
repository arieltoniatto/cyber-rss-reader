"""Inspect pending migrations without changes, or explicitly upgrade the archive."""
import argparse
import json
from pathlib import Path

from config.paths import ARTICLE_DATABASE_FILE
from storage.backup import create_backup
from storage.factory import create_repository,database_url_from_environment
from storage.maintenance import sqlite_status,postgres_status
from storage.retention import RetentionPolicy


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',type=Path,default=ARTICLE_DATABASE_FILE)
    parser.add_argument('--backup-directory',type=Path)
    actions=parser.add_mutually_exclusive_group()
    actions.add_argument('--status',action='store_true',help='Read-only schema inspection (default).')
    actions.add_argument('--upgrade',action='store_true',help='Apply pending migrations transactionally.')
    args=parser.parse_args()
    try:
        url=database_url_from_environment()
        report=postgres_status(url) if url else sqlite_status(args.database)
        backup=None
        if args.upgrade and report['pending']:
            if not url and report['current_version']>0:
                directory=args.backup_directory or args.database.parent/'backups'
                # Keep existing copies; migration backup creation does not rotate them.
                count=len(list(directory.glob('articles-*.sqlite3'))) if directory.exists() else 0
                backup=create_backup(args.database,directory,keep=max(14,count+1))
            create_repository(database_file=args.database,database_url=url,retention=RetentionPolicy())
            report=postgres_status(url) if url else sqlite_status(args.database)
        print(json.dumps({**report,'backup':str(backup) if backup else None},indent=2))
    except ValueError as exc:
        parser.error(str(exc))


if __name__=='__main__':
    main()
