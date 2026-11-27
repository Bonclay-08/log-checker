"""Generate a fake login log with hidden attacks, for testing the analyzer."""

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

from myapp.logs import TIME_FORMAT

Event = tuple[datetime, str, str, str]  # (time, status, user, ip)

START = datetime(2026, 11, 26, 0, 0, 0)
USERS = ["grace", "sam", "amina", "brian", "wanjiru", "otieno", "lucy", "kevin"]
TARGETS = ["admin", "root", "guest", "test", "oracle", "postgres"]


def normal_traffic(rng: random.Random, count: int) -> list[Event]:
    """Office-hours logins (07:00 to 19:00). Each user has one fixed IP."""
    events: list[Event] = []
    for _ in range(count):
        user = rng.choice(USERS)
        ip = f"10.0.1.{USERS.index(user) + 10}"
        status = "FAILED" if rng.random() < 0.05 else "SUCCESS"
        when = START + timedelta(seconds=rng.randrange(7 * 3600, 19 * 3600))
        events.append((when, status, user, ip))
    return events


def brute_force_attack(
    rng: random.Random, ip: str, start: datetime, takes_over: bool
) -> list[Event]:
    """Eight quick failures against one account, optionally ending in a success."""
    events: list[Event] = []
    when = start
    for _ in range(8):
        events.append((when, "FAILED", "admin", ip))
        when += timedelta(seconds=rng.randint(1, 4))
    if takes_over:
        events.append((when, "SUCCESS", "admin", ip))
    return events


def spraying_attack(rng: random.Random, ip: str, start: datetime) -> list[Event]:
    """One failure each against many accounts, spread out to stay quiet."""
    events: list[Event] = []
    when = start
    for user in TARGETS:
        events.append((when, "FAILED", user, ip))
        when += timedelta(seconds=rng.randint(20, 60))
    return events


def hopping_attack(rng: random.Random, start: datetime) -> list[Event]:
    """One account logging in from three different addresses within minutes."""
    events: list[Event] = []
    when = start
    for ip in ("192.0.2.10", "198.51.100.50", "203.0.113.200"):
        events.append((when, "SUCCESS", "grace", ip))
        when += timedelta(seconds=rng.randint(60, 120))
    return events


def generate(count: int = 500, seed: int = 42) -> list[str]:
    """Return log lines, oldest first. The same seed always gives the same log."""
    rng = random.Random(seed)
    events = normal_traffic(rng, count)
    events += brute_force_attack(
        rng, "203.0.113.5", START.replace(hour=3, minute=12), takes_over=True
    )
    events += spraying_attack(rng, "203.0.113.77", START.replace(hour=14, minute=30))
    events += brute_force_attack(
        rng, "198.51.100.23", START.replace(hour=22, minute=5), takes_over=False
    )
    events += hopping_attack(rng, START.replace(hour=16, minute=45))
    events.sort(key=lambda e: e[0])
    return [
        f"{when.strftime(TIME_FORMAT)} {status} {user} {ip}"
        for when, status, user, ip in events
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a fake login log.")
    parser.add_argument("--count", type=int, default=500, help="normal log lines")
    parser.add_argument("--seed", type=int, default=42, help="random seed")
    parser.add_argument(
        "--output", type=Path, default=Path("data/generated.log"), help="output file"
    )
    args = parser.parse_args()
    lines = generate(args.count, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(lines)} lines to {args.output}")


if __name__ == "__main__":
    main()
