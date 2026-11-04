"""UTC normalization with original clock provenance and explicit uncertainty."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# Keep an adjacent offset, including the whitespace form emitted by some appliances.
TIMESTAMP = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?'
    r'(?:\s*(?:[Zz]|[+-]\d{2}:?\d{2}))?'
    r'|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
)
OFFSET = re.compile(r'([Zz]|[+-]\d{2}:?\d{2})$')


@dataclass(frozen=True)
class TimestampInfo:
    utc: str | None
    status: str
    original_timezone: str | None = None
    assumed_timezone: str | None = None
    assumed_year: int | None = None


def _zone(value):
    if value in {'UTC', 'Z', 'z'}:
        return timezone.utc
    if re.fullmatch(r'[+-]\d{2}:?\d{2}', value):
        digits = value[1:].replace(':', '')
        hours, minutes = int(digits[:2]), int(digits[2:])
        if hours > 23 or minutes > 59:
            raise ValueError('Invalid timezone offset')
        return timezone((1 if value[0] == '+' else -1) * timedelta(hours=hours, minutes=minutes))
    return ZoneInfo(value)


def details(value, assume_timezone='UTC', assume_year=None, explicit_timezone=None):
    if explicit_timezone is not None and (not isinstance(explicit_timezone, str) or len(explicit_timezone) > 128):
        return TimestampInfo(None, 'invalid_timezone')
    if value is None or value == '':
        return TimestampInfo(None, 'missing', explicit_timezone)
    if type(value) is bool or not isinstance(value, (str, int, float)):
        return TimestampInfo(None, 'invalid', explicit_timezone)
    original = str(value).strip()
    suffix = OFFSET.search(original) if re.search(r'[T ]\d{2}:', original) else None
    original_zone = explicit_timezone or (suffix[1] if suffix else None)
    assumed_zone, used_year = None, None
    try:
        epoch = isinstance(value, (int, float)) or re.fullmatch(r'[+-]?\d{10}(?:\d{3})?(?:\.\d+)?', original)
        if epoch:
            number = float(value)
            if not math.isfinite(number):
                raise ValueError('Non-finite timestamp')
            if abs(number) >= 10**11:
                number /= 1000
            stamp = datetime.fromtimestamp(number, timezone.utc)
            original_zone = explicit_timezone or 'UTC'
        elif re.match(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+', original):
            if assume_year is None:
                return TimestampInfo(None, 'missing_year', original_zone)
            used_year = assume_year
            stamp = datetime.strptime(f'{assume_year} {original}', '%Y %b %d %H:%M:%S')
        else:
            # fromisoformat accepts reduced/basic dates: those are not event clocks.
            if not re.search(r'[Tt ]\d{2}:?\d{2}', original):
                if re.fullmatch(r'\d{8}', original):
                    datetime.strptime(original, '%Y%m%d')
                else:
                    datetime.fromisoformat(original)
                return TimestampInfo(None, 'missing_time', original_zone)
            cleaned = re.sub(r'\s+([+-]\d{2}:?\d{2}|[Zz])$', r'\1', original)
            stamp = datetime.fromisoformat(cleaned.replace('Z', '+00:00').replace('z', '+00:00'))
        status = 'valid'
        if explicit_timezone:
            try:
                zone = _zone(explicit_timezone)
            except (ValueError, ZoneInfoNotFoundError, TypeError):
                return TimestampInfo(None, 'invalid_timezone', str(explicit_timezone), assumed_year=used_year)
        else:
            zone = None
        if stamp.tzinfo is None:
            if zone is None:
                if assume_timezone is None:
                    return TimestampInfo(None, 'missing_timezone', original_zone, assumed_year=used_year)
                try:
                    zone = _zone(assume_timezone)
                except (ValueError, ZoneInfoNotFoundError):
                    raise ValueError(f'Unknown timezone: {assume_timezone}') from None
                assumed_zone = assume_timezone
                status = 'assumed_timezone'
            first, second = stamp.replace(tzinfo=zone, fold=0), stamp.replace(tzinfo=zone, fold=1)
            # Preserve the existing combined DST uncertainty status for compatibility.
            if first.utcoffset() != second.utcoffset():
                return TimestampInfo(None, 'ambiguous_local_time', original_zone, assumed_zone, used_year)
            stamp = first
        elif zone is not None and not epoch and stamp.astimezone(zone).utcoffset() != stamp.utcoffset():
            return TimestampInfo(None, 'timezone_conflict', original_zone, assumed_year=used_year)
        return TimestampInfo(stamp.astimezone(timezone.utc).isoformat(timespec='microseconds'), status,
                             original_zone, assumed_zone, used_year)
    except ValueError as exc:
        if str(exc).startswith('Unknown timezone:'):
            raise
        return TimestampInfo(None, 'invalid', original_zone, assumed_zone, used_year)
    except (OverflowError, OSError, TypeError):
        return TimestampInfo(None, 'invalid', original_zone, assumed_zone, used_year)


def normalize(value, assume_timezone='UTC', assume_year=None):
    """Compatibility API returning (UTC string, status)."""
    result = details(value, assume_timezone, assume_year)
    return result.utc, result.status
