"""Safe TXT/CSV URL list parsers."""
from __future__ import annotations
import csv
from io import StringIO
from pathlib import Path
from .security import validate_url


def parse_txt(text: str) -> list[dict[str, str]]:
    return _validate_rows({"url": line.strip()} for line in text.splitlines())


def parse_csv(text: str) -> list[dict[str, str]]:
    sample = text[:2048]
    if not sample.strip():
        return []
    dialect = csv.Sniffer().sniff(sample, delimiters=";,")
    return _validate_rows(csv.DictReader(StringIO(text), dialect=dialect))


def _validate_rows(rows) -> list[dict[str, str]]:
    parsed = []
    for row in rows:
        url = (row.get("url") or "").strip()
        if url and not url.startswith("#"):
            parsed.append({**row, "url": validate_url(url)})
    return parsed


def load_urls(path: str | Path) -> list[dict[str, str]]:
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".txt":
        return parse_txt(text)
    if path.suffix.lower() == ".csv":
        return parse_csv(text)
    raise ValueError("Only .txt and .csv files are supported")
