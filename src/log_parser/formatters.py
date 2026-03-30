"""Output formatters for parsed log data."""

from __future__ import annotations

import json
from typing import Any

from .parser import LogEntry, LogLevel
from .patterns import PatternMatch


def format_entry_plain(entry: LogEntry) -> str:
    """Format a log entry as plain text."""
    parts: list[str] = []
    if entry.timestamp:
        parts.append(entry.timestamp.isoformat())
    parts.append(f"[{entry.level.value}]")
    if entry.source:
        parts.append(f"({entry.source})")
    parts.append(entry.message or entry.raw)
    return " ".join(parts)


def format_entry_json(entry: LogEntry) -> dict[str, Any]:
    """Format a log entry as a JSON-serializable dict."""
    result: dict[str, Any] = {
        "line": entry.line_number,
        "level": entry.level.value,
        "message": entry.message or entry.raw,
    }
    if entry.timestamp:
        result["timestamp"] = entry.timestamp.isoformat()
    if entry.source:
        result["source"] = entry.source
    if entry.extras:
        result["extras"] = entry.extras
    return result


def format_entries_json(entries: list[LogEntry]) -> str:
    """Format multiple entries as a JSON array string."""
    return json.dumps(
        [format_entry_json(e) for e in entries],
        indent=2,
        default=str,
    )


def format_summary(entries: list[LogEntry]) -> str:
    """Generate a summary report of parsed log entries."""
    if not entries:
        return "No log entries found."

    total = len(entries)
    level_counts: dict[str, int] = {}
    for entry in entries:
        level = entry.level.value
        level_counts[level] = level_counts.get(level, 0) + 1

    timestamps = [e.timestamp for e in entries if e.timestamp]
    time_range = ""
    if timestamps:
        earliest = min(timestamps)
        latest = max(timestamps)
        time_range = f"\nTime range: {earliest.isoformat()} to {latest.isoformat()}"

    lines = [
        f"Log Summary",
        f"{'=' * 40}",
        f"Total entries: {total}",
    ]

    if time_range:
        lines.append(time_range)

    lines.append("\nLevel distribution:")
    for level in ["FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE", "UNKNOWN"]:
        count = level_counts.get(level, 0)
        if count > 0:
            bar = "#" * min(count, 50)
            lines.append(f"  {level:<8} {count:>5}  {bar}")

    error_entries = [e for e in entries if e.is_error]
    if error_entries:
        lines.append(f"\nFirst error (line {error_entries[0].line_number}):")
        lines.append(f"  {error_entries[0].message[:120]}")

    return "\n".join(lines)


def format_patterns(patterns: list[PatternMatch]) -> str:
    """Format detected patterns as a readable report."""
    if not patterns:
        return "No patterns detected."

    lines = [
        "Pattern Detection Report",
        "=" * 40,
        f"Patterns found: {len(patterns)}",
        "",
    ]

    severity_icons = {"critical": "!!!", "warning": " ! ", "info": " i "}

    for i, pattern in enumerate(patterns, 1):
        icon = severity_icons.get(pattern.severity, "   ")
        lines.append(f"[{icon}] {i}. {pattern.name} ({pattern.severity})")
        lines.append(f"     {pattern.description}")
        if pattern.count > 0:
            lines.append(f"     Affected entries: {pattern.count}")
        lines.append("")

    return "\n".join(lines)
