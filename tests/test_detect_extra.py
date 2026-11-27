from datetime import datetime, timedelta

from myapp.detect import account_hopping, off_hours_logins
from myapp.logs import LoginEvent

DAY = datetime(2026, 11, 26)


def login(hour, minute=0, user="grace", ip="10.0.0.1", success=True):
    when = DAY + timedelta(hours=hour, minutes=minute)
    return LoginEvent(when, success, user, ip)


def test_night_login_is_flagged():
    alerts = off_hours_logins([login(3, 12)])
    assert [a.kind for a in alerts] == ["off_hours_login"]
    assert "03:12" in alerts[0].detail


def test_failed_night_login_is_not_flagged():
    assert off_hours_logins([login(3, success=False)]) == []


def test_daytime_login_is_not_flagged():
    assert off_hours_logins([login(9)]) == []


def test_off_hours_window_edges():
    assert len(off_hours_logins([login(0, 0)])) == 1
    assert len(off_hours_logins([login(4, 59)])) == 1
    assert off_hours_logins([login(5, 0)]) == []


def test_same_user_and_ip_is_reported_once():
    alerts = off_hours_logins([login(1), login(2), login(3)])
    assert len(alerts) == 1


def test_account_hopping_detected():
    events = [
        login(16, 45, ip="1.1.1.1"),
        login(16, 47, ip="2.2.2.2"),
        login(16, 49, ip="3.3.3.3"),
    ]
    alerts = account_hopping(events)
    assert [a.kind for a in alerts] == ["account_hopping"]
    assert alerts[0].ip == "3.3.3.3"


def test_slow_movement_between_ips_is_not_hopping():
    events = [login(8, ip="1.1.1.1"), login(12, ip="2.2.2.2"), login(16, ip="3.3.3.3")]
    assert account_hopping(events) == []


def test_one_ip_many_logins_is_not_hopping():
    events = [login(9, i, ip="1.1.1.1") for i in range(5)]
    assert account_hopping(events) == []


def test_failed_logins_from_many_ips_are_not_hopping():
    events = [login(9, i, ip=f"1.1.1.{i}", success=False) for i in range(5)]
    assert account_hopping(events) == []
