from __future__ import annotations

from rich.console import Console
from rich.table import Table

from parser.models import Article
from topics.models import Topic

console = Console()


def article_table(
    articles: list[Article],
) -> None:

    table = Table(show_lines=False)

    table.add_column("Published", style="cyan", no_wrap=True)
    table.add_column("Source", style="green")
    table.add_column("Category", style="yellow")
    table.add_column("Title", style="white")

    for article in articles:

        published = (
            article.published.strftime("%Y-%m-%d %H:%M")
            if article.published
            else "-"
        )

        table.add_row(
            published,
            article.source,
            article.category,
            article.title,
        )

    console.print(table)


def topic_table(
    topics: list[Topic],
) -> None:

    table = Table()

    table.add_column("Topic", style="cyan")
    table.add_column("Score", justify="right", style="green")
    table.add_column("Frequency", justify="right", style="yellow")

    for topic in topics:

        table.add_row(
            topic.topic,
            f"{topic.score:.3f}",
            str(topic.frequency),
        )

    console.print(table)