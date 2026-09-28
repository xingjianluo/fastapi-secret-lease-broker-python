"""Clock implementations.

All broker logic asks the clock for "now", never calling ``datetime.now``
directly, so tests can deterministically exercise expiry and overlap windows.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


class SystemClock:
    """Real wall clock, always returning timezone-aware UTC."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class ManualClock:
    """Controllable clock for deterministic tests."""

    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now = self._now + timedelta(seconds=seconds)
