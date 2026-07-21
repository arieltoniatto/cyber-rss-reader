import asyncio
from pathlib import Path

from config.loader import ConfigLoader
from feeds.fetcher import RSSFetcher
from parser.parser import RSSParser


async def main():
    BASE_DIR = Path(__file__).resolve().parent.parent

    CONFIG_DIR = BASE_DIR / "config" / "feeds"

    config = ConfigLoader(CONFIG_DIR).load()

    fetcher = RSSFetcher(config)

    feed_results = await fetcher.fetch_all()

    parser = RSSParser()

    articles = parser.parse(feed_results)

    print(f"Downloaded {len(feed_results)} feeds")
    print(f"Parsed {len(articles)} articles")

    for article in articles[:10]:
        print(f"- {article.title}")


if __name__ == "__main__":
    asyncio.run(main())