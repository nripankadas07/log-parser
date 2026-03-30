# log-parser

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests: Passing](https://img.shields.io/badge/Tests-Passing-green.svg)]()

Universal log parser with pattern detection. Feed it any log file and get structured output, level filtering, and automatic anomaly detection â no format configuration needed.

## Why

Debugging production issues means digging through logs in different formats across different services. `log-parser` auto-detects the format (structured logs, syslog, nginx access logs, Python logging) and gives you a unified view with built-in pattern detection for error bursts, repeated failures, time gaps, and traffic anomalies.

## Installation

```bash
pip install -e .
```

Or with dev dependencies:

```bash
pip install -e ".[dev]"
```

## Usage

### CLI

```bash
# Quick summary of a log file
log-parser app.log

# Filter by level
log-parser app.log --level ERROR

# JSON output for piping
log-parser app.log --format json

# Plain text output
log-parser app.log --format plain

# Grep through logs
log-parser app.log --grep "timeout|refused"

# Run pattern detection
log-parser app.log --detect-patterns

# Only process first 100 lines
log-parser app.log --head 100

# Strict mode (fail on unparseable lines)
log-parser app.log --strict
```

### Programmatic

```python
from log_parser.parser import LogParser
from log_parser.patterns import PatternDetector

parser = LogParser()
entries = parser.parse_file("app.log")

print(f"Detected format: {parser.detected_format}")
print(f"Parsed {parser.stats['parsed']}/{parser.stats['total']} lines")

# Filter errors
errors = [e for e in entries if e.is_error]

# Detect patterns
detector = PatternDetector(entries)
patterns = detector.detect_all()
for p in patterns:
    print(f"[{p.severity}] {p.name}: {p.description}")
```

## Supported Formats

The parser auto-detects these log formats from the first matching line:

- **Common structured** â `2024-01-15T10:30:00Z INFO [source] message`
- **Syslog** â `Jan 15 10:30:00 hostname process[pid]: message`
- **Nginx access** â Combined log format
- **Python logging** â `LEVEL:logger:message`
- **JSON-like** â Lines containing `"level"` and `"message"` fields

Custom formats can be added by passing `LogFormat` objects to the parser.

## Pattern Detection

Built-in detectors scan for:

- **Error bursts** â Clusters of errors within a time window
- **Repeated errors** â Same error message appearing multiple times (with number normalization)
- **High error rate** â When errors exceed a configurable threshold of total entries
- **Time gaps** â Suspicious gaps in the log timeline (possible downtime)
- **IP anomalies** â IPs with unusually high request counts (access logs)
- **HTTP errors** â High counts of 4xx/5xx status codes

## API Reference

### `LogParser`

Core parsing engine with auto-detection.

- `parse_line(line, line_number)` â Parse a single line into a `LogEntry`
- `parse_lines(lines)` â Parse multiple lines
- `parse_file(path)` â Parse a file
- `detected_format` â Name of the auto-detected format
- `stats` â Parse statistics (total, parsed, failed)

### `PatternDetector`

Anomaly detection on parsed entries.

- `detect_all()` â Run all detectors, returns `list[PatternMatch]`
- `detect_error_bursts(window_seconds, threshold)`
- `detect_repeated_errors(min_count)`
- `detect_time_gaps(gap_seconds)`
- Individual detectors can be called separately

### `LogLevel`

Enum with standard levels: TRACE, DEBUGD INFO, WARN, ERROR, FATAL, UNKNOWN. Handles aliases (WARNING, CRITICAL, SEVERE).

## Architecture

```
log_parser/
  parser.py      # Core parsing engine, format definitions, timestamp handling
  patterns.py    # Pattern detection and anomaly analysis
  formatters.py  # Output formatting (plain, JSON, summary, pattern reports)
  cli.py         # CLI entry point (click)
```

The flow is: **Log file** â `Parser` auto-detects format â `LogEntry` objects â `PatternDetector` finds anomalies â `Formatters` produce output.

## License

MIT
