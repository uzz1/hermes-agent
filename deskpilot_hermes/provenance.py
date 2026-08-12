from contextlib import contextmanager
from contextvars import ContextVar, copy_context
from dataclasses import dataclass
from typing import Callable, Iterator, Literal, TypeVar


T = TypeVar("T")


@dataclass(frozen=True)
class DeskPilotProvenance:
    entry_point: Literal["ui", "scheduler", "signal", "telegram"]
    sender: str | None
    trace_id: str


_current: ContextVar[DeskPilotProvenance | None] = ContextVar(
    "deskpilot_provenance", default=None
)


@contextmanager
def provenance(value: DeskPilotProvenance) -> Iterator[None]:
    token = _current.set(value)
    try:
        yield
    finally:
        _current.reset(token)


def require_provenance() -> DeskPilotProvenance:
    value = _current.get()
    if value is None:
        raise PermissionError("DeskPilot provenance missing")
    return value


def copied_context_call(function: Callable[[], T]) -> T:
    return copy_context().run(function)
