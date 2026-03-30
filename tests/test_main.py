"""Tests for log-parser."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from log_parser.parser import LogEntry, LogFormat, LogLevel, LogParser, parse_timestamp
from log_parser.patterns import PatternDetector, PatternMatch
from log_parser.formatters import (
    format_entry_json,
    format_entry_plain,
    format_entries_json,
    format_summary,
    format_patterns,
)


# --- LogLevel Tests ---


class TestLogLevel:
    def test_from_string_exact(self) -> None:
        assert LogLevel.from_string("ERROR") == LogLevel.ERROR
        assert LogLevel.from_string("info") == LogLevel.INFO

    def test_from_string_aliases(self) -> None:
        assert LogLevel.from_string("WARNING") == LogLevel.WARN
        assert LogLevel.from_string("CRITICAL") == LogLevel.FATAL
        assert LogLevel.from_string("SEVERE") == LogLevel.ERROR

    def test_from_string_unknown(self) -> None:
        assert LogLevel.from_string("NOTREAL") == LogLevel.UNKNOWN


# --- Timestamp Parsing Tests ---


class TestTimestamp:
    def test_iso_format(self) -> None:
        ts = parse_timestamp("2024-01-15T10:30:00.000Z")
        assert ts is not None
        assert ts.year == 2024
        assert ts.month == 1
        assert ts.hour == 10

    def test_space_separated(self) -> None:
        ts = parse_timestamp("2024-01-15 10:30:00")
        assert ts is not None
        assert ts.minute == 30

    def test_comma_millis(self) -> None:
        ts = parse_timestamp("2024-01-15 10:30:00,123")
        assert ts is not None

    def test_invalid(self) -> None:
        assert parse_timestamp("not a timestamp") is None

    def test_with_explicit_format(self) -> None:
        ts = parse_timestamp("15/Jan/2024:10:30:00 +0000", "%d/%b/%Y:%H:%M:%S %z")
        assert ts is not None
        assert ts.day == 15


# --- Parser Tests ---


COMMON_LOG_LINES = [
    "2024-01-15T10:30:00.000Z INFO [main] Application started",
    "2024-01-15T10:30:01.000Z DEBUG [db] Connection pool initialized",
    "2024-01-15T10:30:05.000Z ERROR [api] Request failed: timeout",
    "2024-01-15T10:30:06.000Z WARN [api] Retrying request",
]

SYSLOG_LINES = [
    "Jan 15 10:30:00 myhost sshd[12345]: Accepted publickey for user",
    "Jan 15 10:30:01 myhost kernel: CPU0: Temperature above threshold",
]

NGINX_LINE = '192.168.1.1 - admin [15/Jan/2024:10:30:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"'

PYTHON_LOG_LINES = [
    "ERROR:myapp.api:Connection refused",
    "INFO:myapp.server:Listening on port 8080",
]


class TestParser:
    def test_parse_common_format(self) -> None:
        parser = LogParser()
        entries = parser.parse_lines(COMMON_LOG_LINES)
        assert len(entries) == 4
        assert entries[0].level == LogLevel.INFO
        assert entries[0].source == "main"
        assert "Application started" in entries[0].message

    def test_parse_detects_format(self) -> None:
        parser = LogParser()
        parser.parse_lines(COMMON_LOG_LINES)
        assert parser.detected_format == "common"

    def test_parse_timestamps(self) -> None:
        parser = LogParser()
        entries = parser.parse_lines(COMMON_LOG_LINES)
        assert entries[0].timestamp is not None
        assert entries[0].timestamp.year == 2024

    def test_parse_error_flag(self) -> None:
        parser = LogParser()
        entries = parser.parse_lines(COMMON_LOG_LINES)
        assert not entries[0].is_error  # INFO
        assert entries[2].is_error  # ERROR

    def test_parse_syslog(self) -> None:
        parser = LogParser()
        entries = parser.parse_lines(SYSLOG_LINES)
        assert len(entries) == 2
        assert parser.detected_format == "syslog"
        assert entries[0].extras.get("process") == "sshd"
        assert entries[0].extras.get("pid") == "12345"

    def test_parse_nginx_access(self) -> None:
        parser = LogParser()
        entries = parser.parse_lines([NGINX_LINE])
        assert len(entries) == 1
        entry = entries[0]
        assert entry.extras.get("remote_addr") == "192.168.1.1"
        assert entry.extras.get("status") == "200"

    def test_parse_python_logging(self) -> None:
        parser = LogParser()
        entries = parser.parse_lines(PYTHON_LOG_LINES)
        assert entries[0].level == LogLevel.ERROR
        assert entries[0].source == "myapp.api"

    def test_parse_stats(self) -> None:
        parser = LogParser()
        parser.parse_lines(COMMON_LOG_LINES)
        stats = parser.stats
        assert stats["total"] == 4
        assert stats["parsed"] == 4
        assert stats["failed"] == 0

    def test_parse_empty_lines(self) -> None:
        parser = LogParser()
        entries = parser.parse_lines(["", "  ", COMMON_LOG_LINES[0]])
        assert parser.stats["failed"] == 2
        assert parser.stats["parsed"] == 1

    def test_parse_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "test.log"
        log_file.write_text("\n".join(COMMON_LOG_LINES))
        parser = LogParser()
        entries = parser.parse_file(str(log_file))
        assert len(entries) == 4

    def test_strict_mode_raises(self) -> None:
        parser = LogParser(strict=True)
        with pytest.raises(ValueError, match="No format matched"):
            parser.parse_line("this is not a log line at all xyz", 1)

    def test_line_numbers(self) -> None:
        parser = LogParser()
        entries = parser.parse_lines(COMMON_LOG_LINES)
        assert entries[0].line_number == 1
        assert entries[3].line_number == 4


# --- Pattern Detection Tests ---


class TestPatternDetector:
    def _make_entries(self, levels: list[str], timestamps: bool = False) -> list[LogEntry]:
        entries = []
        base = datetime(2024, 1, 15, 10, 0, 0)
        for i, level in enumerate(levels):
            ts = None
            if timestamps:
                from datetime import timedelta
                ts = base + timedelta(seconds=i)
            entries.append(
                LogEntry(
                    raw=f"test line {i}",
                    level=LogLevel.from_string(level),
                    message=f"Test message {i}",
                    line_number=i + 1,
                    timestamp=ts,
                )
            )
        return entries

    def test_detect_high_error_rate(self) -> None:
        entries = self._make_entries(["ERROR"] * 4 + ["INFO"] * 6)
        detector = PatternDetector(entries)
        patterns = detector.detect_level_distribution_anomalies(error_threshold=0.3)
        assert len(patterns) == 1
        assert patterns[0].name == "high_error_rate"

    def test_no_anomaly_below_threshold(self) -> None:
        entries = self._make_entries(["ERROR"] * 1 + ["INFO"] * 9)
        detector = PatternDetector(entries)
        patterns = detector.detect_level_distribution_anomalies(error_threshold=0.3)
        assert len(patterns) == 0

    def test_detect_repeated_errors(self) -> None:
        entries = []
        for i in range(5):
            entries.append(
                LogEntry(
                    raw=f"line {i}",
                    level=LogLevel.ERROR,
                    message=f"Connection refused on port 8080",
                    line_number=i + 1,
                )
            )
        detector = PatternDetector(entries)
        patterns = detector.detect_repeated_errors(min_count=3)
        assert len(patterns) == 1
        assert "repeated" in patterns[0].name

    def test_detect_error_burst(self) -> None:
        entries = self._make_entries(["ERROR"] * 6, timestamps=True)
        detector = PatternDetector(entries)
        patterns = detector.detect_error_bursts(window_seconds=60, threshold=5)
        assert len(patterns) == 1
        assert patterns[0].name == "error_burst"

    def test_detect_time_gaps(self) -> None:
        from datetime import timedelta
        base = datetime(2024, 1, 15, 10, 0, 0)
        entries = [
            LogEntry(raw="line 1", timestamp=base, line_number=1),
            LogEntry(raw="line 2", timestamp=base + timedelta(seconds=600), line_number=2),
        ]
        detector = PatternDetector(entries)
        patterns = detector.detect_time_gaps(gap_seconds=300)
        assert len(patterns) == 1
        assert patterns[0].name == "time_gap"

    def test_detect_all_runs(self) -> None:
        entries = self._make_entries(["INFO"] * 10)
        detector = PatternDetector(entries)
        patterns = detector.detect_all()
        # Should run without errors, even if no patterns found
        assert isinstance(patterns, list)

    def test_detect_status_code_errors(self) -> None:
        entries = []
        for i in range(6):
            entries.append(
                LogEntry(
                    raw=f"line {i}",
                    extras={"status": "500", "remote_addr": "1.2.3.4"},
                    line_number=i + 1,
                )
            )
        detector = PatternDetector(entries)
        patterns = detector.detect_status_code_errors(threshold=5)
        assert len(patterns) == 1
        assert patterns[0].name == "http_errors"


# --- Formatter Tests ---


class TestFormatters:
    def test_format_entry_plain(self) -> None:
        entry = LogEntry(
            raw="test",
            level=LogLevel.ERROR,
            message="Something broke",
            timestamp=datetime(2024, 1, 15, 10, 30),
            source="api",
        )
        result = format_entry_plain(entry)
        assert "[ERROR]" in result
        assert "(api)" in result
        assert "Something broke" in result

    def test_format_entry_json(self) -> None:
        entry = LogEntry(
            raw="test",
            level=LogLevel.INFO,
            message="Hello",
            line_number=5,
        )
        result = format_entry_json(entry)
        assert result["level"] == "INFO"
        assert result["message"] == "Hello"
        assert result["line"] == 5

    def test_format_entries_json(self) -> None:
        entries = [
            LogEntry(raw="a", level=LogLevel.INFO, message="A", line_number=1),
            LogEntry(raw="b", level=LogLevel.ERROR, message="B", line_number=2),
        ]
        result = format_entries_json(entries)
        parsed = json.loads(result)
        assert len(parsed) == 2
        assert parsed[0]["level"] == "INFO"

    def test_format_summary(self) -> None:
        entries = [
            LogEntry(raw="a", level=LogLevel.INFO, message="ok", line_number=1),
            LogEntry(raw="b", level=LogLevel.ERROR, message="fail", line_number=2),
        ]
        result = format_summary(entries)
        assert "Total entries: 2" in result
        assert "ERROR" in result

    def test_format_summary_empty(self) -> None:
        assert "No log entries" in format_summary([])

    def test_format_patterns(self) -> None:
        patterns = [
            PatternMatch(
                name="test_pattern",
                description="A test pattern",
                severity="warning",
                entries=[LogEntry(raw="x", line_number=1)],
            )
        ]
        result = format_patterns(patterns)
        assert "test_pattern" in result
        assert "warning" in result

    def test_format_patterns_empty(self) -> None:
        assert "No patterns detected" in format_patterns([])
