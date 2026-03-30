"""Core log parsing engine with pluggable format support."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Iterator


class LogLevel(Enum):
    """Standard log severity levels."""

    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    FATAL = "FATAL"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_string(cls, value: str) -> "LogLevel":
        """Parse a level string, normalizing common variants."""
        normalized = value.strip().upper()
        aliases: dict[str, LogLevel] = {
            "WARNING": cls.WARN,
            "CRITICAL": cls.FATAL,
            "SEVERE": cls.ERROR,
            "FINE": cls.DEBUG,
            "FINER": cls.TRACE,
            "FINEST": cls.TRACE,
        }
        if normalized in aliases:
            return aliases[normalized]
        try:
            return cls(normalized)
        except ValueError:
            return cls.UNKNOWN


@dataclass
class LogEntry:
    """A single parsed log entry."""

    raw: str
    timestamp: datetime | None = None
    level: LogLevel = LogLevel.UNKNOWN
    message: str = ""
    source: str = ""
    extras: dict[str, Any] = field(default_factory=dict)
    line_number: int = 0

    @property
    def is_error(self) -> bool:
        return self.level in (LogLevel.ERROR, LogLevel.FATAL)


@dataclass
class LogFormat:
    """A named log format with a regex pattern and field mapping."""

    name: str
    pattern: re.Pattern[str]
    fields: list[str]
    timestamp_format: str | None = None

    def match(self, line: str) -> dict[str, str] | None:
        """Try to match a line against this format."""
        m = self.pattern.match(line)
        if not m:
            return None
        return {field: m.group(field) for field in self.fields if field in m.groupdict()}


# Built-in log formats
BUILTIN_FORMATS: list[LogFormat] = [
    LogFormat(
        name="common",
        pattern=re.compile(
            r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
            r"(?P<level>[A-Z]+)\s+"
            r"(?:\[(?P<source>[^\]]+)\]\s+)?"
            r"(?P<message>.*)"
        ),
        fields=["timestamp", "level", "source", "message"],
        timestamp_format=None,  # auto-detect
    ),
    LogFormat(
        name="syslog",
        pattern=re.compile(
            r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
            r"(?P<source>\S+)\s+"
            r"(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+"
            r"(?P<message>.*)"
        ),
        fields=["timestamp", "source", "process", "pid", "message"],
        timestamp_format="%b %d %H:%M:%S",
    ),
    LogFormat(
        name="nginx_access",
        pattern=re.compile(
            r'(?P<remote_addr>\S+)\s+-\s+(?P<remote_user>\S+)\s+'
            r"\[(?P<timestamp>[^\]]+)\]\s+"
            r'"(?P<request>[^"]+)"\s+'
            r"(?P<status>\d{3})\s+"
            r"(?P<body_bytes>\d+)\s+"
            r'"(?P<referer>[^"]*)"\s+'
            r'"(?P<user_agent>[^"]*)"'
        ),
        fields=["remote_addr", "remote_user", "timestamp", "request", "status", "body_bytes", "referer", "user_agent"],
        timestamp_format="%d/%b/%Y:%H:%M:%S %z",
    ),
    LogFormat(
        name="python",
        pattern=re.compile(
            r"(?P<level>[A-Z]+):(?P<source>[^:]+):(?P<message>.*)"
        ),
        fields=["level", "source", "message"],
    ),
    LogFormat(
        name="json_like",
        pattern=re.compile(
            r'\{".*"level"\s*:\s*"(?P<level>[^"]+)".*"message"\s*:\s*"(?P<message>[^"]+)".*\}'
        ),
        fields=["level", "message"],
    ),
]

TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%b %d %H:%M:%S",
]


def parse_timestamp(value: str, fmt: str | None = None) -> datetime | None:
    """Try to parse a timestamp string. Returns None on failure."""
    if fmt:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass

    for f in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(value, f)
        except ValueError:
            continue
    return None


class LogParser:
    """Universal log parser that auto-detects formats."""

    def __init__(
        self,
        formats: list[LogFormat] | None = None,
        strict: bool = False,
    ) -> None:
        self.formats = formats or list(BUILTIN_FORMATS)
        self.strict = strict
        self._detected_format: LogFormat | None = None
        self._stats = {"total": 0, "parsed": 0, "failed": 0}

    @property
    def detected_format(self) -> str | None:
        """Name of the auto-detected log format, if any."""
        return self._detected_format.name if self._detected_format else None

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def parse_line(self, line: str, line_number: int = 0) -> LogEntry:
        """Parse a single log line."""
        self._stats["total"] += 1
        line = line.rstrip("\n\r")

        if not line.strip():
            self._stats["failed"] += 1
            return LogEntry(raw=line, line_number=line_number)

        # Try detected format first for performance
        if self._detected_format:
            entry = self._try_format(self._detected_format, line, line_number)
            if entry:
                self._stats["parsed"] += 1
                return entry

        # Try all formats
        for fmt in self.formats:
            entry = self._try_format(fmt, line, line_number)
            if entry:
                if self._detected_format is None:
                    self._detected_format = fmt
                self._stats["parsed"] += 1
                return entry

        self._stats["failed"] += 1
        if self.strict:
            raise ValueError(f"No format matched line {line_number}: {line[:80]}")
        return LogEntry(raw=line, message=line, line_number=line_number)

    def _try_format(
        self, fmt: LogFormat, line: str, line_number: int
    ) -> LogEntry | None:
        """Try to parse a line with a specific format."""
        matched = fmt.match(line)
        if not matched:
            return None

        timestamp = None
        ts_str = matched.get("timestamp")
        if ts_str:
            timestamp = parse_timestamp(ts_str, fmt.timestamp_format)

        level = LogLevel.UNKNOWN
        level_str = matched.get("level")
        if level_str:
            level = LogLevel.from_string(level_str)

        message = matched.get("message", "")
        source = matched.get("source", "")

        extras = {
            k: v for k, v in matched.items()
            if k not in ("timestamp", "level", "message", "source") and v is not None
        }

        return LogEntry(
            raw=line,
            timestamp=timestamp,
            level=level,
            message=message.strip(),
            source=source.strip(),
            extras=extras,
            line_number=line_number,
        )

    def parse_lines(self, lines: Iterator[str] | list[str]) -> list[LogEntry]:
        """Parse multiple log lines."""
        return [
            self.parse_line(line, i + 1)
            for i, line in enumerate(lines)
        ]

    def parse_file(self, path: str) -> list[LogEntry]:
        """Parse a log file."""
        with open(path) as f:
            return self.parse_lines(f)
