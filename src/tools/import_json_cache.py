import argparse
from pathlib import Path

from config.paths import ARTICLE_CACHE_FILE, ARTICLE_DATABASE_FILE
from storage.sqlite_storage import SQLiteArticleRepository


def main() -> None:
    parser = argparse.ArgumentParser(description="Import the legacy JSON cache once into SQLite.")
    parser.add_argument("--input", type=Path, default=ARTICLE_CACHE_FILE)
    parser.add_argument("--database", type=Path, default=ARTICLE_DATABASE_FILE)
    args = parser.parse_args()
    count = SQLiteArticleRepository(args.database).import_json(args.input)
    print(f"Imported {count} articles. The original JSON was preserved.")


if __name__ == "__main__":
    main()
