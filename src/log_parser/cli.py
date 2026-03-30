"""CLI entry point for log-parser."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from .formatters import (
    format_entries_json,
    format_entry_plain,
    format_patterns,
    format_summary,
)
from .parser import LogLevel, LogParser
from .patterns import PatternDetector


@click.command()
@click.argument("logfile", type=click.Path(exists=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["plain", "json", "summary"]),
    default="summary",
    help="Output format (default: summary).",
)
@click.option(
    "--level",
    "min_level",
    type=click.Choice(["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"]),
    default=None,
    help="Filter: only show entries at or above this level.",
)
@click.option(
    "--grep",
    "grep_pattern",
    default=None,
    help="Filter: only show entries matching this regex.",
)
@click.option(
    "--detect-patterns",
    is_flag=True,
    default=False,
    help="Run pattern detection on the log entries.",
)
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="Fail on lines that don't match any known format.",
)
@click.option(
    "--head",
    "head_n",
    type=int,
    default=None,
    help="Only process the first N lines.",
)
def main(
    logfile: str,
    output_format: str,
    min_level: str | None,
    grep_pattern: str | None,
    detect_patterns: bool,
    strict: bool,
    head_n: int | None,
) -> None:
    """Parse and analyze log files.

    Supports common log formats: structured logs, syslog, nginx access logs,
    Python logging, and more. Auto-detects the format from the first matching line.
    """
    parser = LogParser(strict=strict)

    # Read and parse
    path = Path(logfile)
    with open(path) as f:
        lines = f.readlines()

    if head_n is not None:
        lines = lines[:head_n]

    entries = parser.parse_lines(lines)

    # Filters
    level_order = [
        LogLevel.TRACE,
        LogLevel.DEBUG,
        LogLevel.INFO,
        LogLevel.WARN,
        LogLevel.ERROR,
        LogLevel.FATAL,
    ]

    if min_level:
        target = LogLevel.from_string(min_level)
        target_idx = level_order.index(target) if target in level_order else 0
        entries = [
            e
            for e in entries
            if e.level in level_order[target_idx:]
            or e.level == LogLevel.UNKNOWN
        ]

    if grep_pattern:
        import re

        regex = re.compile(grep_pattern, re.IGNORECASE)
        entries = [e for e in entries if regex.search(e.raw)]

    # Output
    if output_format == "json":
        click.echo(format_entries_json(entries))
    elif output_format == "plain":
        for entry in entries:
            click.echo(format_entry_plain(entry))
    else:
        click.echo(format_summary(entries))
        if parser.detected_format:
            click.echo(f"\nDetected format: {parser.detected_format}")
        stats = parser.stats
        click.echo(
            f"Parse stats: {stats['parsed']}/{stats['total']} lines parsed, "
            f"{stats['failed']} failed"
        )

    # Pattern detection
    if detect_patterns:
        click.echo("\n")
        detector = PatternDetector(entries)
        patterns = detector.detect_all()
        click.echo(format_patterns(patterns))
