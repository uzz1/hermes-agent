import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID


_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)


def nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def validate_uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("UUID must be a string")
    parsed = UUID(value)
    if str(parsed) != value:
        raise ValueError("UUID must use canonical lowercase representation")
    return value


def validate_sha256(value: Any) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError("digest must be canonical SHA-256")
    return value


def parse_rfc3339(value: Any) -> datetime:
    if not isinstance(value, str) or _RFC3339.fullmatch(value) is None:
        raise ValueError("timestamp must be strict RFC3339")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed


def validate_bounded_future(value: Any, maximum_seconds: float = 300.0) -> datetime:
    parsed = parse_rfc3339(value)
    remaining = (parsed - datetime.now(UTC)).total_seconds()
    if remaining <= 0.0 or remaining > maximum_seconds:
        raise ValueError("timestamp outside allowed future window")
    return parsed
