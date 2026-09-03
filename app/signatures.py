from __future__ import annotations
import json
from pathlib import Path
DEFAULT_PATH = Path(__file__).resolve().parents[1] / "config" / "signatures.json"
def load_signatures(path: str | Path = DEFAULT_PATH) -> dict:
    with Path(path).open(encoding="utf-8") as file: return json.load(file)
