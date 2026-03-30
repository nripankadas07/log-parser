"""Pattern detection for log entries â find anomalies, bursts, and recurring issues."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from .parser import LogEntry, LogLevel


@dataclass
class PatternMatch:
    """A detected pattern in the log stream."""

    name: str
    description: str
    severity: str  # "info", "warning", "critical"
    entries: list[LogEntry] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.entries)


class PatternDetector:
    """Detect common patterns and anomalies in parsed log entries."""

    def __init__(self, entries: list[LogEntry]) -> None:
        self.entries = entries

    def detect_all(self) -> list[PatternMatch]:
        """Run all built-in pattern detectors."""
        patterns: list[PatternMatch] = []
        patterns.extend(self.detect_error_bursts())
        patterns.extend(self.detect_repeated_errors())
        patterns.extend(self.detect_level_distribution_anomalies())
        patterns.extend(self.detect_time_gaps())
        patterns.extend(self.detect_ip_anomalies())
        patterns.extend(self.detect_status_code_errors())
        return [p for p in patterns if p.count > 0]

    def detect_error_bursts(
        self, window_seconds: int = 60, threshold: int = 5
    ) -> list[PatternMatch]:
        """Detect bursts of errors within a time window."""
        errors = [e for e in self.entries if e.is_error and e.timestamp]
        if len(errors) < threshold:
            return []

        bursts: list[PatternMatch] = []
        i = 0
        while i < len(errors):
            window_start = errors[i].timestamp
            assert window_start is not None
            window_end = window_start + timedelta(seconds=window_seconds)
            burst_entries = []
            j = i
            while j < len(errors):
                ts = errors[j].timestamp
                assert ts is not None
                if ts <= window_end:
                    burst_entries.append(errors[j])
                    j += 1
                else:
                    break

            if len(burst_entries) >= threshold:
                bursts.append(
                    PatternMatch(
                        name="error_burst",
                        description=(
                            f"{len(burst_entries)} errors in {window_seconds}s "
                            f"starting at {window_start.isoformat()}"
                        ),
                        severity="critical",
                        entries=burst_entries,
                        metadata={
                            "window_seconds": window_seconds,
                            "start": window_start.isoformat(),
                        },
                    )
                )
                i = j  # skip past this burst
            else:
                i += 1

        return bursts

    def detect_repeated_errors(self, min_count: int = 3) -> list[PatternMatch]:
        """Find error messages that repeat frequently."""
        error_msgs: Counter[str] = Counter()
        error_entries: dict[str, list[LogEntry]] = defaultdict(list)

        for entry in self.entries:
            if entry.is_error and entry.message:
                # Normalize: strip numbers to group similar messages
                normalized = re.sub(r"\d+", "N", entry.message)
                error_msgs[normalized] += 1
                error_entries[normalized].append(entry)

        patterns: list[PatternMatch] = []
        for msg, count in error_msgs.most_common():
            if count >= min_count:
                patterns.append(
                    PatternMatch(
                        name="repeated_error",
                        description=f"Error repeated {count}x: {msg[:100]}",
                        severity="warning",
                        entries=error_entries[msg],
                        metadata={"normalized_message": msg, "count": count},
                    )
                )
        return patterns

    def detect_level_distribution_anomalies(
        self, error_threshold: float = 0.3
    ) -> list[PatternMatch]:
        """Flag when error/fatal entries exceed a proportion of total."""
        if not self.entries:
            return []

        level_counts: Counter[LogLevel] = Counter(e.level for e in self.entries)
        total = len(self.entries)
        error_count = level_counts.get(LogLevel.ERROR, 0) + level_counts.get(
            LogLevel.FATAL, 0
        )
        error_ratio = error_count / total

        if error_ratio >= error_threshold:
            return [
                PatternMatch(
                    name="high_error_rate",
                    description=(
                        f"{error_ratio:.0%} of log lines are errors "
                        f"({error_count}/{total})"
                    ),
                    severity="critical",
                    entries=[e for e in self.entries if e.is_error],
                    metadata={
                        "error_ratio": round(error_ratio, 3),
                        "distribution": {
                            level.value: count
                            for level, count in level_counts.items()
                        },
                    },
                )
            ]
        return []

    def detect_time_gaps(
        self, gap_seconds: int = 300
    ) -> list[PatternMatch]:
        """Detect suspicious gaps in the log timeline."""
        timestamped = [e for e in self.entries if e.timestamp]
        if len(timestamped) < 2:
            return []

        sorted_entries = sorted(timestamped, key=lambda e: e.timestamp)  # type: ignore[arg-type]
        gaps: list[PatternMatch] = []

        for i in range(1, len(sorted_entries)):
            prev_ts = sorted_entries[i - 1].timestamp
            curr_ts = sorted_entries[i].timestamp
            assert prev_ts and curr_ts
            delta = (curr_ts - prev_ts).total_seconds()
            if delta >= gap_seconds:
                gaps.append(
                    PatternMatch(
                        name="time_gap",
                        description=(
                            f"{delta:.0f}s gap between lines "
                            f"{sorted_entries[i-1].line_number} and "
                            f"{sorted_entries[i].line_number}"
                        ),
                        severity="warning",
                        entries=[sorted_entries[i - 1], sorted_entries[i]],
                        metadata={
                            "gap_seconds": delta,
                            "from": prev_ts.isoformat(),
                            "to": curr_ts.isoformat(),
                        },
                    )
                )

        return gaps

    def detect_ip_anomalies(self, threshold: int = 50) -> list[PatternMatch]:
        """Detect IPs with unusually high request counts (for access logs)."""
        ip_counts: Counter[str] = Counter()
        ip_entries: dict[str, list[LogEntry]] = defaultdict(list)

        for entry in self.entries:
            ip = entry.extras.get("remote_addr")
            if ip:
                ip_counts[ip] += 1
                ip_entries[ip].append(entry)

        patterns: list[PatternMatch] = []
        for ip, count in ip_counts.most_common():
            if count >= threshold:
                patterns.append(
                    PatternMatch(
                        name="high_frequency_ip",
                        description=f"IP {ip} made {count} requests",
                        severity="warning",
                        entries=ip_entries[ip][:10],  # sample
                        metadata={"ip": ip, "count": count},
                    )
                )
        return patterns

    def detect_status_code_errors(self, threshold: int = 5) -> list[PatternMatch]:
        """Detect high counts of HTTP 4xx/5xx status codes."""
        status_counts: Counter[str] = Counter()
        status_entries: dict[str, list[LogEntry]] = defaultdict(list)

        for entry in self.entries:
            status = entry.extras.get("status")
            if status and str(status).startswith(("4", "5")):
                status_counts[str(status)] += 1
                status_entries[str(status)].append(entry)

        patterns: list[PatternMatch] = []
        for status, count in status_counts.most_common():
            if count >= threshold:
                patterns.append(
                    PatternMatch(
                        name="http_errors",
                        description=f"HTTP {status} occurred {count} times",
                        severity="warning" if status.startswith("4") else "critical",
                        entries=status_entries[status][:10],
                        metadata={"status_code": status, "count": count},
                    )
                )
        return patterns
