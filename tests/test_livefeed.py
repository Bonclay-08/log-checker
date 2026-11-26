import pytest

from myapp.live import Monitor
from myapp.livefeed import LiveFeed
from myapp.web import app, feed


def attack_lines(ip="9.9.9.9", count=8):
    return [f"2026-11-26 12:00:{i:02d} FAILED admin {ip}" for i in range(count)]


@pytest.fixture(autouse=True)
def fresh_feed():
    """Start every test with an empty shared feed."""
    feed.monitor = Monitor()
    feed.alerts.clear()
    feed.lines = 0


def test_new_feed_is_empty():
    snapshot = LiveFeed().snapshot()
    assert snapshot == {"watching": None, "lines": 0, "alerts": []}


def test_attack_lines_produce_one_alert():
    live_feed = LiveFeed()
    for line in attack_lines():
        live_feed.handle(line)
    snapshot = live_feed.snapshot()
    assert snapshot["lines"] == 8
    assert [a["kind"] for a in snapshot["alerts"]] == ["brute_force"]
    assert snapshot["alerts"][0]["ip"] == "9.9.9.9"


def test_newest_alert_comes_first():
    live_feed = LiveFeed()
    for line in attack_lines("1.1.1.1") + attack_lines("2.2.2.2"):
        live_feed.handle(line)
    ips = [a["ip"] for a in live_feed.snapshot()["alerts"]]
    assert ips[0] == "2.2.2.2"


def test_old_alerts_are_dropped_when_the_list_is_full():
    live_feed = LiveFeed(max_alerts=2)
    for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
        for line in attack_lines(ip):
            live_feed.handle(line)
    assert len(live_feed.snapshot()["alerts"]) == 2


def test_api_returns_alerts_as_json():
    for line in attack_lines():
        feed.handle(line)
    response = app.test_client().get("/api/live")
    assert response.status_code == 200
    data = response.get_json()
    assert data["lines"] == 8
    assert data["alerts"][0]["kind"] == "brute_force"


def test_live_page_loads_and_never_uses_innerhtml():
    response = app.test_client().get("/live")
    assert response.status_code == 200
    assert b"Live Monitor" in response.data
    assert b"innerHTML" not in response.data
