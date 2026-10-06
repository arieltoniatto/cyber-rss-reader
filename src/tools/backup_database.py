import argparse
import sqlite3
from pathlib import Path

from config.paths import ARTICLE_DATABASE_FILE, BACKUP_DIRECTORY
from storage.backup import create_backup


def main() -> None:
    parser = argparse.ArgumentParser(description='Create an online, verified SQLite snapshot.')
    parser.add_argument('--database', type=Path, default=ARTICLE_DATABASE_FILE)
    parser.add_argument('--directory', type=Path, default=BACKUP_DIRECTORY)
    parser.add_argument('--keep', type=int, default=14)
    args = parser.parse_args()
    try:
        path = create_backup(args.database, args.directory, keep=args.keep)
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(1, f'Backup failed: {exc}\n')
    print(f'Backup verified: {path}')


if __name__ == '__main__':
    main()
