"""Clock and local timezone for the web panel stores.

The stores read the time and the local timezone only through this module, so
tests and the Go port's golden-vector generators can run them at a fixed
instant in a fixed timezone, independent of the host clock and ``TZ``.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, tzinfo

_clock: Callable[[], datetime] | None = None
_tz: tzinfo | None = None
_rng: random.Random | None = None


def now() -> datetime:
    """Current panel-local time (timezone-aware)."""
    if _clock is not None:
        return localize(_clock())
    if _tz is not None:
        return datetime.now(_tz)
    return datetime.now().astimezone()


def localize(dt: datetime) -> datetime:
    """Attach the panel-local timezone to a naive datetime, or convert an aware one.

    Matches ``datetime.astimezone()``: naive values are taken to be local time.
    """
    if _tz is None:
        return dt.astimezone()
    if dt.tzinfo is None:
        return dt.replace(tzinfo=_tz)
    return dt.astimezone(_tz)


def uniform(a: float, b: float) -> float:
    """Random float in [a, b] (seedable for tests)."""
    return (_rng or random).uniform(a, b)


@contextmanager
def fixed(
    clock: Callable[[], datetime] | None = None,
    *,
    tz: tzinfo | None = None,
    seed: int | None = None,
) -> Iterator[None]:
    """Run the panel with a fake clock, local timezone and/or random seed."""
    global _clock, _tz, _rng
    saved = (_clock, _tz, _rng)
    _clock = clock
    _tz = tz
    _rng = random.Random(seed) if seed is not None else None
    try:
        yield
    finally:
        _clock, _tz, _rng = saved
