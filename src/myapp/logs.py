"""Parse login logs into typed events.

Two log formats are understood:

1. Simple, one login attempt per line:
    2026-11-25 09:15:01 FAILED admin 10.0.0.5

2. OpenSSH (sshd) lines, as written to /var/log/auth.log on Linux:
    Nov 25 09:15:01 srv sshd[8]: Failed password for admin from 1.2.3.4 port 22
"""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# "Nov 25 09:15:01 host sshd[812]: message"  (classic syslog, no year)
SYSLOG_LINE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+sshd(?:\[\d+\])?:\s+(?P<message>.*)$"
)
# "2026-11-25T09:15:01.123456+00:00 host sshd[812]: message"  (newer systems)
ISO_LINE = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}T\S+)\s+\S+\s+sshd(?:\[\d+\])?:\s+(?P<message>.*)$"
)
FAILED = re.compile(
    r"^Failed (?:password|publickey|keyboard-interactive/pam) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
)
ACCEPTED = re.compile(
    r"^Accepted (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from (?P<ip>\S+) port \d+"
)


@dataclass(frozen=True)
class LoginEvent:
    timestamp: datetime
    success: bool
    user: str
    ip: str


def parse_simple_line(line: str) -> LoginEvent | None:
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


def _split_ssh_line(line: str, year: int | None) -> tuple[datetime, str] | None:
    """Split an sshd log line into its timestamp and its message."""
    text = line.strip()
    match = SYSLOG_LINE.match(text)
    if match:
        now = datetime.now()
        stamp = f"{year or now.year} {match['month']} {match['day']} {match['time']}"
        try:
            when = datetime.strptime(stamp, "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        if year is None and when > now + timedelta(days=1):
            # syslog has no year: a December line read in January is last year's
            try:
                when = when.replace(year=when.year - 1)
            except ValueError:
                return None
        return when, match["message"]
    match = ISO_LINE.match(text)
    if match:
        try:
            when = datetime.fromisoformat(match["stamp"]).replace(tzinfo=None)
        except ValueError:
            return None
        return when, match["message"]
    return None


def parse_ssh_line(line: str, year: int | None = None) -> LoginEvent | None:
    """Parse an OpenSSH login line. Other sshd messages return None.

    Syslog timestamps have no year, so `year` (default: this year) fills it in.
    """
    parts = _split_ssh_line(line, year)
    if parts is None:
        return None
    when, message = parts
    for pattern, success in ((FAILED, False), (ACCEPTED, True)):
        found = pattern.match(message)
        if found:
            return LoginEvent(when, success, found["user"], found["ip"])
    return None


def parse_line(line: str) -> LoginEvent | None:
    """Parse a log line in either supported format, or return None."""
    event = parse_simple_line(line)
    if event is not None:
        return event
    return parse_ssh_line(line)


def read_log(path: Path) -> list[LoginEvent]:
    """Read a log file, skip invalid lines, and return events oldest first."""
    events: list[LoginEvent] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line)
            if event is not None:
                events.append(event)
    return sorted(events, key=lambda e: e.timestamp)
