import argparse
import sqlite3
from pathlib import Path

from storage.backup import restore_backup


def main() -> None:
    parser = argparse.ArgumentParser(description='Verify and restore a snapshot into a new SQLite file.')
    parser.add_argument('--backup', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        path = restore_backup(args.backup, args.output)
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(1, f'Restore failed: {exc}\n')
    print(f'Restore verified: {path}')


if __name__ == '__main__':
    main()
