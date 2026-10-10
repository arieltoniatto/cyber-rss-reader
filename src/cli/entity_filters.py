"""Validation shared by commands that filter enriched article metadata."""
import typer


def nonempty_filter(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value:
        raise typer.BadParameter("Use a non-empty filter value.")
    return value
