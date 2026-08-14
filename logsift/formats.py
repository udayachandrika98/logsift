"""Log format profiles and line parsing.

Each profile knows how to turn one raw line into an Entry. Parsing is
regex-based and deliberately tolerant: a line that doesn't match is returned
as an unparsed Entry rather than raising, so one malformed line never kills
a 10 million line scan.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime

# Levels ordered by severity so filtering can be "this level and above".
LEVELS = ("trace", "debug", "info", "warn", "error", "fatal")
_LEVEL_RANK = {name: index for index, name in enumerate(LEVELS)}
_LEVEL_ALIASES = {
    "warning": "warn",
    "err": "error",
    "critical": "fatal",
    "crit": "fatal",
    "panic": "fatal",
    "notice": "info",
}


def normalise_level(raw: str | None) -> str | None:
    if not raw:
        return None
    lowered = raw.strip().lower()
    lowered = _LEVEL_ALIASES.get(lowered, lowered)
    return lowered if lowered in _LEVEL_RANK else None


def level_rank(level: str | None) -> int:
    return _LEVEL_RANK.get(level or "", -1)


@dataclass
class Entry:
    """One parsed log line."""

    raw: str
    lineno: int
    timestamp: datetime | None = None
    level: str | None = None
    message: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    parsed: bool = True

    def get(self, key: str) -> str | None:
        """Look up a field by name, including the built-in ones."""
        if key == "level":
            return self.level
        if key == "message":
            return self.message
        return self.fields.get(key)


@dataclass
class Profile:
    name: str
    pattern: re.Pattern[str]
    time_format: str | None = None
    time_group: str = "ts"
    # Syslog timestamps carry no year. Rather than defaulting to 1900 (which
    # breaks every time comparison) we assume the current year.
    assume_year: bool = False

    def parse(self, line: str, lineno: int) -> Entry:
        match = self.pattern.match(line)
        if not match:
            return Entry(raw=line, lineno=lineno, message=line, parsed=False)

        groups = {k: v for k, v in match.groupdict().items() if v is not None}
        timestamp = None
        raw_time = groups.pop(self.time_group, None)
        if raw_time and self.time_format:
            value, fmt = raw_time, self.time_format
            if self.assume_year:
                value, fmt = f"{datetime.now().year} {value}", f"%Y {fmt}"
            try:
                timestamp = datetime.strptime(value, fmt)
            except ValueError:
                timestamp = None

        level = normalise_level(groups.pop("level", None))
        message = groups.pop("message", "")

        return Entry(
            raw=line,
            lineno=lineno,
            timestamp=timestamp,
            level=level,
            message=message,
            fields=groups,
        )


SYSLOG = Profile(
    name="syslog",
    pattern=re.compile(
        r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<process>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.*)$"
    ),
    time_format="%b %d %H:%M:%S",
    assume_year=True,
)

APP = Profile(
    name="app",
    pattern=re.compile(
        r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})(?:[.,]\d+)?Z?\s+"
        r"\[?(?P<level>[A-Za-z]+)\]?\s+"
        r"(?:(?P<logger>[\w.]+)\s+[-:]\s+)?"
        r"(?P<message>.*)$"
    ),
    time_format="%Y-%m-%d %H:%M:%S",
)

NGINX = Profile(
    name="nginx",
    pattern=re.compile(
        r'^(?P<client>\S+)\s+\S+\s+(?P<user>\S+)\s+'
        r'\[(?P<ts>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>\S+)[^"]*"\s+'
        r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
    ),
    time_format="%d/%b/%Y:%H:%M:%S %z",
)


class JSONProfile:
    """Newline-delimited JSON logs -- every key becomes a queryable field."""

    name = "json"

    TIME_KEYS = ("timestamp", "time", "ts", "@timestamp")
    LEVEL_KEYS = ("level", "severity", "lvl")
    MESSAGE_KEYS = ("message", "msg", "event")

    def parse(self, line: str, lineno: int) -> Entry:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return Entry(raw=line, lineno=lineno, message=line, parsed=False)
        if not isinstance(payload, dict):
            return Entry(raw=line, lineno=lineno, message=line, parsed=False)

        timestamp = None
        for key in self.TIME_KEYS:
            if key in payload:
                timestamp = self._parse_time(str(payload.pop(key)))
                break

        level = None
        for key in self.LEVEL_KEYS:
            if key in payload:
                level = normalise_level(str(payload.pop(key)))
                break

        message = ""
        for key in self.MESSAGE_KEYS:
            if key in payload:
                message = str(payload.pop(key))
                break

        return Entry(
            raw=line,
            lineno=lineno,
            timestamp=timestamp,
            level=level,
            message=message,
            fields={k: str(v) for k, v in payload.items()},
        )

    @staticmethod
    def _parse_time(value: str) -> datetime | None:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None


PROFILES: dict[str, Profile | JSONProfile] = {
    "syslog": SYSLOG,
    "app": APP,
    "nginx": NGINX,
    "json": JSONProfile(),
}


def detect(sample: list[str]) -> str:
    """Guess the profile from the first few lines, most specific first."""
    best, best_hits = "app", 0
    for name in ("json", "nginx", "syslog", "app"):
        profile = PROFILES[name]
        hits = sum(1 for line in sample if line.strip() and profile.parse(line, 0).parsed)
        if hits > best_hits:
            best, best_hits = name, hits
    return best


def parse_stream(lines, profile_name: str):
    """Lazily parse an iterable of raw lines into Entries."""
    profile = PROFILES[profile_name]
    for lineno, line in enumerate(lines, start=1):
        line = line.rstrip("\n")
        if line.strip():
            yield profile.parse(line, lineno)
