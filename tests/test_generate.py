from myapp.detect import run_all
from myapp.generate import generate
from myapp.logs import parse_line


def test_same_seed_gives_same_log():
    assert generate(100, seed=1) == generate(100, seed=1)


def test_different_seed_gives_different_log():
    assert generate(100, seed=1) != generate(100, seed=2)


def test_every_line_is_valid():
    assert all(parse_line(line) is not None for line in generate(200))


def test_hidden_attacks_are_detected():
    events = [parse_line(line) for line in generate(500)]
    alerts = run_all([e for e in events if e is not None])
    found = {(a.kind, a.ip) for a in alerts}
    assert ("brute_force", "203.0.113.5") in found
    assert ("brute_force", "198.51.100.23") in found
    assert ("password_spraying", "203.0.113.77") in found
    assert ("success_after_failures", "203.0.113.5") in found
