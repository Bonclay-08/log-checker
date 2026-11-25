from datetime import datetime, timedelta

from myapp.detect import brute_force, password_spraying, run_all, success_after_failures
from myapp.logs import LoginEvent
from myapp.report import build_report

BASE = datetime(2026, 11, 25, 9, 0, 0)


def ev(seconds, ip="10.0.0.5", user="admin", success=False):
    return LoginEvent(BASE + timedelta(seconds=seconds), success, user, ip)


def test_brute_force_detected():
    events = [ev(i * 5) for i in range(5)]
    alerts = brute_force(events, max_failures=5, window_seconds=60)
    assert [a.ip for a in alerts] == ["10.0.0.5"]


def test_slow_failures_are_not_brute_force():
    events = [ev(i * 120) for i in range(5)]
    assert brute_force(events, max_failures=5, window_seconds=60) == []


def test_password_spraying_detected():
    events = [ev(i, user=f"user{i}", ip="10.0.0.77") for i in range(4)]
    alerts = password_spraying(events, min_users=4)
    assert [a.kind for a in alerts] == ["password_spraying"]


def test_success_after_failures_detected():
    events = [ev(i) for i in range(3)] + [ev(10, success=True)]
    alerts = success_after_failures(events, min_failures=3)
    assert len(alerts) == 1
    assert alerts[0].kind == "success_after_failures"


def test_no_events_means_no_alerts():
    assert run_all([]) == []


def test_report_counts():
    events = [ev(0), ev(1), ev(2, success=True)]
    report = build_report(events, [])
    assert report["total_events"] == 3
    assert report["failed"] == 2
    assert report["succeeded"] == 1
