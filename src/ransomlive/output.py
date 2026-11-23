import html
import json
import re
from collections.abc import Iterator
from itertools import islice
from typing import TextIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ransomlive.api import JSONValue

SOURCE = "https://ransomware.live"
_URL = re.compile(r"(?i)\b(https?|ftp|wss?)://([^\s/<>\"'?#]+)")
_DOMAIN = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z0-9-]+\b")
_AUTOLINK = re.compile(
    r"(?i)(?:\b[a-z][a-z0-9+.-]*://|"
    r"\b(?:[\w-]+\.)+(?:[^\W\d_][\w-]+|xn--[\w-]+)\b|"
    r"[\w.+-]+@[\w.-]+)"
)
_MARKDOWN = re.compile(r"([\\`*_{}\[\]!~|])")
_SCHEME = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ws": "wxs", "wss": "wxss"}
_DOMAIN_FIELDS = {
    "domain",
    "domains",
    "website",
    "host",
    "hostname",
    "url",
    "urls",
    "onion",
    "locations",
    "fqdn",
    "slug",
    "post_url",
}
_MAX_ROWS = 100
_MAX_CELL = 180
_PREFERRED = ("victim", "group", "name", "country", "activity", "date", "discovered", "title", "id")


def defang(data: JSONValue, field: str = "") -> JSONValue:
    if isinstance(data, dict):
        return {key: defang(value, key.lower()) for key, value in data.items()}
    if isinstance(data, list):
        return [defang(value, field) for value in data]
    if isinstance(data, str):
        text = _URL.sub(
            lambda match: _SCHEME[match[1].lower()] + "://" + match[2].replace(".", "[.]"),
            data,
        )
        return (
            _DOMAIN.sub(lambda match: match[0].replace(".", "[.]"), text)
            if (field in _DOMAIN_FIELDS)
            else text
        )
    return data


def _cell(value: JSONValue) -> str:
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, separators=(", ", ": "))
    value = "".join(
        char if char.isprintable() else ascii(char)[1:-1] for char in value[: _MAX_CELL + 1]
    )
    return value if len(value) <= _MAX_CELL else value[:_MAX_CELL] + "..."


def _preview(
    data: JSONValue,
) -> tuple[list[str], Iterator[list[JSONValue]], str]:
    if isinstance(data, dict):
        collections = [(key, value) for key, value in data.items() if isinstance(value, list)]
        if len(collections) == 1:
            key, value = collections[0]
            columns, rows, _ = _preview(value)
            title = f"{_cell(key)} ({len(value)} entries)"
            if key == "matches" and isinstance(count := data.get("profiles_checked"), int):
                title += f" across {count} local profiles"
            if key == "locations" and isinstance(group := data.get("group"), str):
                title = f"{_cell(group)}: {title}"
            return columns, rows, title
        return ["Field", "Value"], ([key, value] for key, value in data.items()), "Response"
    if isinstance(data, list):
        records = [row for row in data if isinstance(row, dict)]
        if data and len(records) == len(data):
            keys = dict.fromkeys(key for row in records for key in row)
            if keys:
                order = (
                    ("match", "victim", "group", "website", "discovered", "permalink", "post_url")
                    if "match" in keys and "permalink" in keys
                    else ("group", "match", "matched_name", "altname", "victims")
                    if "matched_name" in keys
                    else (*_PREFERRED, "url", "title", "available", "enabled", "type")
                )
                preferred = [key for key in order if key in keys]
                columns = (preferred + [key for key in keys if key not in preferred])[:7]
                return columns, ([row.get(key) for key in columns] for row in records), "Results"
        return ["Value"], ([item] for item in data), "Results"
    return ["Value"], iter([[data]]), "Response"


def _markdown_cell(text: str) -> str:
    escaped = html.escape(text, quote=False)
    if _AUTOLINK.search(text):
        escaped = escaped.translate({ord(char): f"&#{ord(char)};" for char in "\\`*_[]!~|:."})
        return f"<code>{escaped}</code>"
    escaped = _MARKDOWN.sub(r"\\\1", escaped)
    escaped = re.sub(r"^(\s*)(#{1,6}|[-+])(?=\s)", r"\1\\\2", escaped)
    return re.sub(r"^(\s*\d+)([.)])(?=\s)", r"\1\\\2", escaped)


def render(data: JSONValue, output: TextIO, fmt: str, *, defanged: bool = False) -> None:
    if defanged:
        data = defang(data)
    if fmt == "auto":
        fmt = "table" if output.isatty() else "json"
    if fmt == "json":
        print(
            json.dumps({"source": SOURCE, "data": data}, ensure_ascii=True, indent=2), file=output
        )
        return
    columns, rows, title = _preview(data)
    labels = [_cell(column) for column in columns]
    cells = [[_cell(value) for value in row] for row in islice(rows, _MAX_ROWS)]
    limit_hint = "Preview: up to 100 rows; use --format json for all fields and rows."
    if fmt == "markdown":
        print(f"Source: [Ransomware.live]({SOURCE})\n\n{limit_hint}\n", file=output)
        if isinstance(data, dict) and any(
            isinstance(data.get(key), list) for key in ("matches", "locations")
        ):
            print(f"{_markdown_cell(title)}\n", file=output)
        print("| " + " | ".join(map(_markdown_cell, labels)) + " |", file=output)
        print("| " + " | ".join("---" for _ in labels) + " |", file=output)
        for row in cells:
            print("| " + " | ".join(map(_markdown_cell, row)) + " |", file=output)
    else:
        console = Console(file=output, markup=False, highlight=False)
        table = Table(title=Text(title), show_lines=True)
        for label in labels:
            table.add_column(Text(label))
        for row in cells:
            table.add_row(*(Text(value) for value in row))
        console.print(table)
        console.print(f"Source: Ransomware.live ({SOURCE})\n{limit_hint}")
