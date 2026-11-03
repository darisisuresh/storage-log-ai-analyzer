from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterable
from pathlib import Path

from .models import Event
from .vendors import detect_component, detect_product, detect_severity, detect_vendor

SUPPORTED_SUFFIXES = {".log", ".txt", ".json", ".jsonl", ".csv"}
TIMESTAMP = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)


def discover(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in SUPPORTED_SUFFIXES)
    raise FileNotFoundError(f"Input path does not exist: {path}")


def _records(path: Path) -> Iterable[tuple[int, str, dict | None]]:
    if path.suffix.lower() == ".csv":
        with path.open(encoding="utf-8", errors="replace", newline="") as handle:
            for number, row in enumerate(csv.DictReader(handle), 2):
                yield number, " ".join(str(value) for value in row.values()), row
        return
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(data, (list, dict)):
            raise ValueError(f"{path}: JSON must contain an object or an array")
        records = data if isinstance(data, list) else data.get("events", [data])
        if not isinstance(records, list):
            raise ValueError(f"{path}: 'events' must be an array")
        for number, row in enumerate(records, 1):
            yield number, json.dumps(row, ensure_ascii=False), row if isinstance(row, dict) else None
        return
    with path.open(encoding="utf-8", errors="replace") as handle:
        for number, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line:
                continue
            row = None
            if path.suffix.lower() == ".jsonl":
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    pass
            yield number, line, row if isinstance(row, dict) else None


def parse_file(path: Path, vendor_override: str = "auto") -> list[Event]:
    records = list(_records(path))
    corpus = "\n".join(text for _, text, _ in records[:500])
    file_vendor = detect_vendor(corpus) if vendor_override == "auto" else vendor_override
    events: list[Event] = []
    for number, text, row in records:
        row = row if isinstance(row, dict) else {}
        message = str(row.get("message") or row.get("msg") or row.get("description") or text)
        timestamp_match = TIMESTAMP.search(text)
        timestamp = str(row.get("timestamp") or row.get("time") or (timestamp_match.group("ts") if timestamp_match else "")) or None
        raw_severity = str(row.get("severity") or row.get("level") or "").lower()
        severity = raw_severity if raw_severity in {"critical", "high", "medium", "low"} else detect_severity(text)
        line_vendor = detect_vendor(text)
        event_vendor = (line_vendor if line_vendor != "unknown" else file_vendor) if vendor_override == "auto" else vendor_override
        events.append(Event(timestamp, event_vendor, detect_product(text), severity, detect_component(text), message, str(path), number))
    return events


def ingest(path: Path, vendor_override: str = "auto") -> tuple[list[Path], list[Event]]:
    files = discover(path)
    events: list[Event] = []
    for file in files:
        events.extend(parse_file(file, vendor_override))
    return files, events
