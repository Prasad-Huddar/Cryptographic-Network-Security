"""
Consistent Timezone Conversion & Display Utilities (UTC Storage -> Asia/Kolkata IST Display).

Design Guarantees:
- Database records and cryptographic validations ALWAYS remain in UTC.
- Display formatting converts UTC timestamps into Asia/Kolkata (IST, UTC+05:30)
  formatted as: '25 Nov 2026, 10:01:06 PM IST'.
- Prevents double conversion: timezone-aware datetimes already in IST (+05:30) or
  strings already ending with ' IST' are never shifted a second time.
"""
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
    IST_TZ = ZoneInfo('Asia/Kolkata')
except Exception:
    # India Standard Time does not observe DST and is fixed at UTC+05:30.
    IST_TZ = timezone(timedelta(hours=5, minutes=30), name='IST')

IST_DISPLAY_FORMAT = '%d %b %Y, %I:%M:%S %p IST'
IST_TIME_BUCKET_FORMAT = '%I:%M %p IST'


def to_utc_aware(value: datetime | str | None) -> datetime | None:
    """
    Normalize a naive UTC datetime, timezone-aware datetime, or ISO-8601 string
    into a timezone-aware UTC datetime object without double shifting.
    """
    if value is None or value == '':
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        iso_str = raw[:-1] + '+00:00' if raw.endswith('Z') else raw
        try:
            parsed = datetime.fromisoformat(iso_str)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    return None


def to_ist(value: datetime | str | None) -> datetime | None:
    """
    Convert a UTC (naive or aware) datetime or ISO-8601 string into an
    Asia/Kolkata (IST) timezone-aware datetime without double-converting values
    that are already in IST.
    """
    utc_dt = to_utc_aware(value)
    if utc_dt is None:
        return None
    return utc_dt.astimezone(IST_TZ)


def format_ist(value: datetime | str | None) -> str:
    """
    Format a UTC datetime or ISO-8601 timestamp into IST display format:
    '25 Nov 2026, 10:01:06 PM IST'.
    Safe against double-conversion for already-formatted IST strings or IST-aware datetimes.
    """
    if value is None or value == '':
        return 'N/A'

    if isinstance(value, str) and value.strip().endswith(' IST'):
        return value.strip()

    ist_dt = to_ist(value)
    if ist_dt is None:
        return str(value)
    return ist_dt.strftime(IST_DISPLAY_FORMAT)


def format_ist_time_bucket(value: datetime | str | None) -> str:
    """Format a timestamp into an IST minute bucket label for live charts (e.g. '10:01 PM IST')."""
    ist_dt = to_ist(value)
    if ist_dt is None:
        return 'Unknown'
    return ist_dt.strftime(IST_TIME_BUCKET_FORMAT)


def format_utc_iso(value: datetime | str | None) -> str:
    """Return canonical UTC ISO-8601 string (with 'Z') for audit reference."""
    utc_dt = to_utc_aware(value)
    if utc_dt is None:
        return ''
    return utc_dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def now_ist_formatted() -> str:
    """Return current server time formatted in Asia/Kolkata IST."""
    return datetime.now(timezone.utc).astimezone(IST_TZ).strftime(IST_DISPLAY_FORMAT)
