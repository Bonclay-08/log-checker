import random
import threading
from datetime import datetime, timedelta
from itertools import islice

from myapp.live import Monitor, follow
from myapp.simulate import entries, format_line


def failures(start_hour, count, ip="9.9.9.9"):
    return [
        f"2026-11-26 {start_hour}:00:{i:02d} FAILED admin {ip}" for i in range(count)
    ]


def test_garbage_lines_are_ignored():
    assert Monitor().add("garbage") == []


def test_attack_is_reported_only_once():
    monitor = Monitor()
    alerts = [a for line in failures("12", 8) for a in monitor.add(line)]
    assert [a.kind for a in alerts] == ["brute_force"]


def test_same_attack_is_reported_again_after_it_expires():
    monitor = Monitor()
    lines = failures("12", 5) + ["2026-11-26 13:00:00 SUCCESS sam 10.0.1.11"]
    lines += failures("14", 5)
    alerts = [a for line in lines for a in monitor.add(line)]
    assert [a.kind for a in alerts].count("brute_force") == 2


def test_simulated_stream_triggers_alerts():
    rng = random.Random(1)
    base = datetime(2026, 11, 26, 12, 0, 0)
    stream = islice(entries(rng, attack_every=10), 100)
    monitor = Monitor()
    kinds = set()
    for i, entry in enumerate(stream):
        for alert in monitor.add(format_line(base + timedelta(seconds=i), entry)):
            kinds.add(alert.kind)
    assert kinds & {"brute_force", "password_spraying"}


def test_follow_reads_existing_lines_from_start(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("one\ntwo\n", encoding="utf-8")
    lines = follow(log, poll_seconds=0.01, from_start=True, timeout=2)
    assert next(lines) == "one\n"
    assert next(lines) == "two\n"


def test_follow_sees_lines_added_later(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("old\n", encoding="utf-8")

    def append():
        with open(log, "a", encoding="utf-8") as f:
            f.write("new\n")

    timer = threading.Timer(0.2, append)
    timer.start()
    lines = follow(log, poll_seconds=0.01, timeout=5)
    assert next(lines) == "new\n"
    timer.join()


def test_follow_stops_after_timeout(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("", encoding="utf-8")
    assert list(follow(log, poll_seconds=0.01, timeout=0.1)) == []
