"""Parse login logs into typed events."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


@dataclass(frozen=True)
class LoginEvent:
    timestamp: datetime
    success: bool
    user: str
    ip: str


def parse_line(line: str) -> LoginEvent | None:
    """Parse 'DATE TIME STATUS USER IP'. Return None if the line is invalid."""
    parts = line.split()
    if len(parts) != 5:
        return None
    date, time, status, user, ip = parts
    if status not in ("SUCCESS", "FAILED"):
        return None
    try:
        timestamp = datetime.strptime(f"{date} {time}", TIME_FORMAT)
    except ValueError:
        return None
    return LoginEvent(timestamp, status == "SUCCESS", user, ip)


def read_log(path: Path) -> list[LoginEvent]:
    """Read a log file, skip invalid lines, and return events oldest first."""
    events: list[LoginEvent] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            event = parse_line(line)
            if event is not None:
                events.append(event)
    return sorted(events, key=lambda e: e.timestamp)
