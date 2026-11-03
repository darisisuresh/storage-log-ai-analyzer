from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

import ijson
from ijson.common import ObjectBuilder

from .models import Event
from .vendors import detect_component, detect_product, detect_severity, detect_vendor

SUPPORTED_SUFFIXES = {'.log', '.txt', '.json', '.jsonl', '.csv'}
MAX_RECORD = 1024 * 1024
TIMESTAMP = re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')
DEVICE = re.compile(r'\b(?:array|hostname|host|device|system)(?:[_ -]?(?:id|name))?\s*[:=]\s*["\']?([\w.:-]+)', re.I)
RESOURCE = re.compile(r'\b(disk|drive|ssd|nvme|controller|node|port|volume|lun|pool)\s*(?:id\s*[:=]?\s*|[#: =]\s*)?([\w.-]+)', re.I)
RESOURCE_STOP = {'failure', 'failures', 'failed', 'healthy', 'cleared', 'restored', 'recovered', 'offline', 'online', 'is', 'was', 'has', 'not', 'error', 'errors', 'degraded', 'critical', 'full'}
SYSLOG_HOST = re.compile(r'^(?:<\d+>)?(?:\d+\s+)?(?:\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+')


def discover(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        # File names, unlike events, remain bounded by the explicit file-count limit.
        paths = []
        for item in path.rglob('*'):
            if item.is_file() and item.suffix.lower() in SUPPORTED_SUFFIXES:
                paths.append(item)
                if len(paths) > 10000:
                    raise ValueError('More than 10000 input files; split the scan into batches')
        return sorted(paths)
    raise FileNotFoundError(f'Input path does not exist: {path}')


class _JSONReader:
    """Bound string tokens and nesting before the incremental parser buffers them."""
    def __init__(self, raw):
        self.raw = raw
        self.quoted = False
        self.escape = False
        self.length = 0
        self.depth = 0

    def read(self, size=-1):
        data = self.raw.read(min(size, 65536) if size >= 0 else 65536)
        for char in data:
            if self.quoted:
                self.length += 1
                if self.length > MAX_RECORD:
                    raise ValueError('JSON string exceeds the 1 MiB record limit')
                if self.escape:
                    self.escape = False
                elif char == 92:
                    self.escape = True
                elif char == 34:
                    self.quoted = False
            elif char == 34:
                self.quoted, self.length = True, 0
            elif char in (91, 123):
                self.depth += 1
                if self.depth > 64:
                    raise ValueError('JSON nesting exceeds 64 levels')
            elif char in (93, 125):
                self.depth -= 1
        return data


def _json_records(path: Path):
    with path.open('rb') as handle:
        events = ijson.parse(_JSONReader(handle), use_float=True)
        root = next(events, None)
        if root is None or root[1] not in {'start_array', 'start_map'}:
            raise ValueError(f'{path}: JSON must contain an object or an array')
        array = root[1] == 'start_array'
        envelope = False
        target = 'item' if array else None
        root_builder = None if array else ObjectBuilder()
        if root_builder:
            root_builder.event('start_map', None)
        builder, depth, size, number = None, 0, 0, 0
        for prefix, event, value in events:
            if not array and prefix == 'events' and not envelope:
                if event != 'start_array':
                    raise ValueError(f"{path}: 'events' must be an array")
                envelope, target, root_builder, size = True, 'events.item', None, 0
                continue
            if target and prefix == target and builder is None:
                builder, depth, size = ObjectBuilder(), 0, 0
            if builder is not None:
                size += len(str(value)) if value is not None else 1
                if size > MAX_RECORD:
                    raise ValueError(f'{path}: JSON record exceeds 1 MiB')
                builder.event(event, value)
                depth += (event in {'start_map', 'start_array'}) - (event in {'end_map', 'end_array'})
                if depth == 0:
                    number += 1
                    row = builder.value
                    yield number, json.dumps(row, ensure_ascii=False), row if isinstance(row, dict) else None
                    builder = None
            elif root_builder is not None:
                size += len(str(value)) if value is not None else 1
                if size > MAX_RECORD:
                    raise ValueError(f'{path}: JSON record exceeds 1 MiB')
                root_builder.event(event, value)
                if prefix == '' and event == 'end_map':
                    row = root_builder.value
                    yield 1, json.dumps(row, ensure_ascii=False), row
        if builder is not None:
            raise ValueError(f'{path}: incomplete JSON record')


class _Lines:
    def __init__(self, handle):
        self.handle, self.size = handle, 0

    def __iter__(self):
        return self

    def __next__(self):
        line = self.handle.readline(MAX_RECORD + 1)
        if not line:
            raise StopIteration
        self.size += len(line)
        if self.size > MAX_RECORD:
            raise ValueError('Input record exceeds 1 MiB; split oversized records')
        return line


def _records(path: Path) -> Iterable[tuple[int, str, dict | None]]:
    try:
        if path.suffix.lower() == '.json':
            yield from _json_records(path)
            return
        with path.open(encoding='utf-8', errors='replace', newline='') as handle:
            lines = _Lines(handle)
            if path.suffix.lower() == '.csv':
                reader = csv.DictReader(lines)
                for row in reader:
                    yield reader.line_num, ' '.join(str(v) for v in row.values()), row
                    lines.size = 0
                return
            for number, raw in enumerate(lines, 1):
                lines.size = 0
                line = raw.strip()
                if not line:
                    continue
                row = None
                if path.suffix.lower() == '.jsonl':
                    try:
                        value = json.loads(line)
                        row = value if isinstance(value, dict) else None
                    except json.JSONDecodeError:
                        pass
                yield number, line, row
    except (ijson.JSONError, csv.Error, RecursionError) as exc:
        raise ValueError(f'{path}: invalid or excessively nested input ({type(exc).__name__})') from None


def _identity(row, text):
    device = next((str(row[k]) for k in ('array_id', 'array', 'hostname', 'host', 'device_id', 'device', 'system') if row.get(k)), None)
    match = DEVICE.search(text) if not device else None
    if match:
        device = match[1]
    if not device:
        match = SYSLOG_HOST.search(text)
        device = match[1] if match else None
    resource = ''
    for key in ('resource', 'disk_id', 'drive_id', 'component_id'):
        if row.get(key) is not None:
            resource = str(row[key]).lower()
            if key in {'disk_id', 'drive_id'}:
                resource = 'disk:' + resource
            break
    if not resource:
        match = RESOURCE.search(text)
        if match and match[2].lower() not in RESOURCE_STOP:
            resource = f'{match[1].lower()}:{match[2].lower()}'
            resource = resource.replace('drive:', 'disk:').replace('ssd:', 'disk:')
    return device, resource


def iter_file(path: Path, vendor_override: str = 'auto') -> Iterator[Event]:
    for number, text, row in _records(path):
        row = row or {}
        message = str(row.get('message') or row.get('msg') or row.get('description') or text)
        timestamp_match = TIMESTAMP.search(text)
        timestamp = str(row.get('timestamp') or row.get('time') or (timestamp_match['ts'] if timestamp_match else '')) or None
        raw_severity = str(row.get('severity') or row.get('level') or '').lower()
        severity = raw_severity if raw_severity in {'critical', 'high', 'medium', 'low'} else detect_severity(text)
        explicit_vendor = str(row.get('vendor', '')).lower()
        vendor = explicit_vendor if explicit_vendor in {'pure', 'emc', 'hpe'} else detect_vendor(message)
        if vendor_override != 'auto':
            vendor = vendor_override
        device, resource = _identity(row, message)
        if len(device or "") > 256 or len(resource) > 256 or len(timestamp or "") > 128:
            raise ValueError(f"{path}:{number}: oversized identity or timestamp field")
        yield Event(timestamp, vendor, detect_product(message), severity, detect_component(message), message, str(path), number, device, resource)


def parse_file(path: Path, vendor_override: str = 'auto') -> list[Event]:
    """Compatibility helper for small integrations; CLI uses iter_file, never this list."""
    result, text_size = [], 0
    for event in iter_file(path, vendor_override):
        text_size += len(event.message) + len(event.source)
        if len(result) >= 10000 or text_size > 8 * MAX_RECORD:
            raise ValueError('parse_file is limited to 10000 events; use iter_file for streaming')
        result.append(event)
    return result


def ingest(path: Path, vendor_override: str = 'auto'):
    files = discover(path)
    return files, (event for file in files for event in iter_file(file, vendor_override))
