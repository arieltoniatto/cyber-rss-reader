from datetime import date, datetime, time, timezone


def normalize_datetime(value: date | datetime) -> datetime:
    """Legacy dates and naive timestamps are interpreted as UTC."""
    if not isinstance(value, datetime):
        value = datetime.combine(value, time.min)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def publication_key(article) -> datetime:
    return (normalize_datetime(article.published) if article.published
            else datetime.min.replace(tzinfo=timezone.utc))
