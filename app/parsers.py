from __future__ import annotations
import csv
from pathlib import Path
from .security import validate_url
def load_urls(path: str | Path) -> list[dict[str, str]]:
    path = Path(path); rows = []
    if path.suffix.lower() == ".txt": source = ({"url": line.strip()} for line in path.read_text(encoding="utf-8-sig").splitlines())
    elif path.suffix.lower() == ".csv":
        with path.open(encoding="utf-8-sig", newline="") as stream:
            sample = stream.read(2048); stream.seek(0); dialect = csv.Sniffer().sniff(sample, delimiters=";,"); source = list(csv.DictReader(stream, dialect=dialect))
    else: raise ValueError("Only .txt and .csv files are supported")
    for item in source:
        url = (item.get("url") or "").strip()
        if url and not url.startswith("#"): rows.append({**item, "url": validate_url(url)})
    return rows
