"""Filtering and aggregation over parsed log entries."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta

from .formats import Entry, level_rank, normalise_level


@dataclass
class Filter:
    """A predicate over entries. Every criterion is optional and ANDed."""

    min_level: str | None = None
    pattern: re.Pattern[str] | None = None
    invert: bool = False
    since: datetime | None = None
    until: datetime | None = None
    field_equals: dict[str, str] | None = None

    def matches(self, entry: Entry) -> bool:
        if self.min_level is not None:
            # Entries with no level are kept -- a missing level is not proof
            # the line is unimportant, and dropping them silently loses data.
            if entry.level is not None and level_rank(entry.level) < level_rank(self.min_level):
                return False

        if self.since is not None and entry.timestamp is not None:
            if entry.timestamp < self.since:
                return False
        if self.until is not None and entry.timestamp is not None:
            if entry.timestamp > self.until:
                return False

        if self.field_equals:
            for key, expected in self.field_equals.items():
                if (entry.get(key) or "") != expected:
                    return False

        if self.pattern is not None:
            hit = bool(self.pattern.search(entry.raw))
            if hit == self.invert:
                return False

        return True

    def apply(self, entries: Iterable[Entry]) -> Iterator[Entry]:
        return (entry for entry in entries if self.matches(entry))


def parse_field_filters(pairs: list[str]) -> dict[str, str]:
    """Turn ['status=500', 'method=POST'] into a dict."""
    result = {}
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(f"field filter {pair!r} must be in KEY=VALUE form")
        key, _, value = pair.partition("=")
        result[key.strip()] = value.strip()
    return result


def parse_since(value: str, now: datetime) -> datetime:
    """Accept either an ISO timestamp or a relative offset like '15m' or '2h'."""
    match = re.fullmatch(r"(\d+)([smhd])", value.strip())
    if match:
        amount, unit = int(match.group(1)), match.group(2)
        delta = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]
        return now - timedelta(**{delta: amount})
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(
            f"cannot read {value!r} as a time -- use ISO format or an offset like 30m"
        ) from exc


@dataclass
class Summary:
    total: int
    unparsed: int
    by_level: Counter
    first: datetime | None
    last: datetime | None

    @property
    def error_count(self) -> int:
        return sum(
            count
            for level, count in self.by_level.items()
            if level_rank(level) >= level_rank("error")
        )

    @property
    def error_rate(self) -> float:
        return self.error_count / self.total if self.total else 0.0

    @property
    def span(self) -> timedelta | None:
        if self.first and self.last:
            return self.last - self.first
        return None


def summarise(entries: Iterable[Entry]) -> Summary:
    total = unparsed = 0
    by_level: Counter = Counter()
    first = last = None

    for entry in entries:
        total += 1
        if not entry.parsed:
            unparsed += 1
        by_level[entry.level or "unknown"] += 1
        if entry.timestamp is not None:
            if first is None or entry.timestamp < first:
                first = entry.timestamp
            if last is None or entry.timestamp > last:
                last = entry.timestamp

    return Summary(total, unparsed, by_level, first, last)


def top(entries: Iterable[Entry], key: str, limit: int = 10) -> list[tuple[str, int]]:
    """The most common values of a field."""
    counts: Counter = Counter()
    for entry in entries:
        value = entry.get(key)
        if value:
            counts[value] += 1
    return counts.most_common(limit)


def buckets(
    entries: Iterable[Entry], width: timedelta, level: str | None = None
) -> list[tuple[datetime, int]]:
    """Count entries per fixed-width time bucket.

    Entries without a timestamp are skipped -- they can't be placed on a
    timeline. If `level` is given, only entries at that level or above count.
    """
    if width.total_seconds() <= 0:
        raise ValueError("bucket width must be positive")

    threshold = level_rank(normalise_level(level)) if level else None
    counts: dict[datetime, int] = defaultdict(int)

    for entry in entries:
        if entry.timestamp is None:
            continue
        if threshold is not None and level_rank(entry.level) < threshold:
            continue
        epoch_seconds = entry.timestamp.timestamp()
        floored = epoch_seconds - (epoch_seconds % width.total_seconds())
        counts[datetime.fromtimestamp(floored, tz=entry.timestamp.tzinfo)] += 1

    return sorted(counts.items())


def spikes(series: list[tuple[datetime, int]], factor: float = 3.0) -> list[tuple[datetime, int]]:
    """Buckets whose count is `factor` times the median or more.

    The median is used rather than the mean so that one enormous spike
    doesn't raise the baseline and mask the others.
    """
    if len(series) < 3:
        return []
    counts = sorted(count for _, count in series)
    median = counts[len(counts) // 2]
    if median == 0:
        median = 1
    return [(when, count) for when, count in series if count >= median * factor]
