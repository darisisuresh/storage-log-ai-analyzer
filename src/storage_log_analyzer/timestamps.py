"""Explicit timestamp normalization; original values and assumptions remain visible."""
from datetime import datetime, timezone
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def normalize(value, assume_timezone='UTC', assume_year=None):
    if type(value) is bool:
        return None, 'invalid'
    if value is None or value == '':
        return None, 'missing'
    original = str(value).strip()
    try:
        if isinstance(value, (int, float)) or (original.replace('.', '', 1).isdigit() and len(original.split('.')[0]) in {10, 13}):
            number = float(value)
            if number > 10**11:
                number /= 1000
            stamp = datetime.fromtimestamp(number, timezone.utc)
        else:
            if re.fullmatch(r'\d{4}-\d{2}-\d{2}', original):
                return None, 'missing_time'
            try:
                stamp = datetime.fromisoformat(original.replace('Z', '+00:00'))
            except ValueError:
                if assume_year is None:
                    return None, 'missing_year' if len(original) >= 3 and original[:3].isalpha() else 'invalid'
                stamp = datetime.strptime(f'{assume_year} {original}', '%Y %b %d %H:%M:%S')
        status = 'valid'
        if stamp.tzinfo is None:
            if assume_timezone is None:
                return None, 'missing_timezone'
            zone = ZoneInfo(assume_timezone)
            # Reject ambiguous/nonexistent wall-clock times rather than pick a DST fold.
            first, second = stamp.replace(tzinfo=zone, fold=0), stamp.replace(tzinfo=zone, fold=1)
            if first.utcoffset() != second.utcoffset():
                return None, 'ambiguous_local_time'
            stamp = first
            status = 'assumed_timezone'
        return stamp.astimezone(timezone.utc).isoformat(timespec='microseconds'), status
    except (ValueError, OverflowError, OSError, TypeError):
        return None, 'invalid'
    except ZoneInfoNotFoundError:
        raise ValueError(f'Unknown timezone: {assume_timezone}') from None
