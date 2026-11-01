"""Jinja filters for dates and AWS identifiers."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import quote

from jinja2 import Environment


def ago(when: datetime | None, missing: str = "no record") -> str:
    if when is None:
        return missing
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    days = (datetime.now(UTC) - when).days
    if days <= 0:
        return "today"
    if days == 1:
        return "yesterday"
    if days < 60:
        return f"{days} days ago"
    if days < 730:
        return f"{days // 30} months ago"
    return f"{days // 365} years ago"


def short_date(when: datetime | None) -> str:
    return f"{when:%d %b %Y}" if when else "unknown"


def date_time(when: datetime | None) -> str:
    return f"{when:%d %b %Y, %H:%M} UTC" if when else "unknown"


def tri(value: bool | None, yes: str = "Yes", no: str = "No", unknown: str = "Not assessed") -> str:
    if value is None:
        return unknown
    return yes if value else no


def register(env: Environment) -> None:
    env.filters["ago"] = ago
    env.filters["short_date"] = short_date
    env.filters["date_time"] = date_time
    env.filters["tri"] = tri
    env.filters["q"] = lambda value: quote(str(value), safe="")
