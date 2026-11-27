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


def off_hours_logins(
    events: list[LoginEvent], start_hour: int = 0, end_hour: int = 5
) -> list[Alert]:
    """Flag successful logins in the small hours (default 00:00 to 04:59).

    Each user and IP pair is reported once.
    """
    seen: set[tuple[str, str]] = set()
    alerts: list[Alert] = []
    for event in events:
        in_window = start_hour <= event.timestamp.hour < end_hour
        if not event.success or not in_window:
            continue
        key = (event.user, event.ip)
        if key in seen:
            continue
        seen.add(key)
        detail = f"{event.user} logged in at {event.timestamp:%H:%M}"
        alerts.append(Alert("off_hours_login", event.ip, detail))
    return alerts


def account_hopping(
    events: list[LoginEvent], min_ips: int = 3, window_minutes: int = 10
) -> list[Alert]:
    """Flag one account logging in successfully from several IPs within minutes.

    A real person rarely moves between addresses that fast, so the account may
    be in the hands of someone else. The alert shows the most recent IP.
    """
    window = timedelta(minutes=window_minutes)
    logins_by_user: dict[str, list[LoginEvent]] = defaultdict(list)
    for event in events:
        if event.success:
            logins_by_user[event.user].append(event)

    alerts: list[Alert] = []
    for user, logins in logins_by_user.items():
        start = 0
        peak = 0
        last_ip = ""
        for end in range(len(logins)):
            while logins[end].timestamp - logins[start].timestamp > window:
                start += 1
            distinct = len({e.ip for e in logins[start : end + 1]})
            if distinct > peak:
                peak = distinct
                last_ip = logins[end].ip
        if peak >= min_ips:
            detail = f"{user} logged in from {peak} IPs within {window_minutes} min"
            alerts.append(Alert("account_hopping", last_ip, detail))
    return sorted(alerts, key=lambda a: a.detail)


def run_all(
    events: list[LoginEvent], max_failures: int = 5, window_seconds: int = 60
) -> list[Alert]:
    """Run every detector and return all alerts."""
    return (
        brute_force(events, max_failures, window_seconds)
        + password_spraying(events)
        + success_after_failures(events)
        + off_hours_logins(events)
        + account_hopping(events)
    )
