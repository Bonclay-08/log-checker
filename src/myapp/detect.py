"""Detect suspicious login patterns."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from myapp.logs import LoginEvent


@dataclass(frozen=True)
class Alert:
    kind: str
    ip: str
    detail: str


def brute_force(
    events: list[LoginEvent], max_failures: int = 5, window_seconds: int = 60
) -> list[Alert]:
    """Flag IPs with max_failures or more failed logins inside one time window."""
    window = timedelta(seconds=window_seconds)
    failures_by_ip: dict[str, list[LoginEvent]] = defaultdict(list)
    for event in events:
        if not event.success:
            failures_by_ip[event.ip].append(event)

    alerts: list[Alert] = []
    for ip, failures in failures_by_ip.items():
        start = 0
        peak = 0
        for end in range(len(failures)):
            while failures[end].timestamp - failures[start].timestamp > window:
                start += 1
            peak = max(peak, end - start + 1)
        if peak >= max_failures:
            detail = f"{peak} failed logins within {window_seconds}s"
            alerts.append(Alert("brute_force", ip, detail))
    return sorted(alerts, key=lambda a: a.ip)


def password_spraying(events: list[LoginEvent], min_users: int = 4) -> list[Alert]:
    """Flag IPs that failed against many different accounts."""
    users_by_ip: dict[str, set[str]] = defaultdict(set)
    for event in events:
        if not event.success:
            users_by_ip[event.ip].add(event.user)
    alerts = [
        Alert("password_spraying", ip, f"{len(users)} different accounts targeted")
        for ip, users in users_by_ip.items()
        if len(users) >= min_users
    ]
    return sorted(alerts, key=lambda a: a.ip)


def success_after_failures(
    events: list[LoginEvent], min_failures: int = 3
) -> list[Alert]:
    """Flag a successful login that follows a streak of failures from the same IP."""
    streak: dict[str, int] = defaultdict(int)
    alerts: list[Alert] = []
    for event in events:
        if not event.success:
            streak[event.ip] += 1
            continue
        if streak[event.ip] >= min_failures:
            detail = f"{event.user} logged in after {streak[event.ip]} failures"
            alerts.append(Alert("success_after_failures", event.ip, detail))
        streak[event.ip] = 0
    return alerts


def run_all(
    events: list[LoginEvent], max_failures: int = 5, window_seconds: int = 60
) -> list[Alert]:
    """Run every detector and return all alerts."""
    return (
        brute_force(events, max_failures, window_seconds)
        + password_spraying(events)
        + success_after_failures(events)
    )
