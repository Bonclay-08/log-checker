"""Write fake login events to a log file in real time, to test live mode."""

import argparse
import random
import time
from collections.abc import Iterator
from datetime import datetime
from itertools import islice
from pathlib import Path

from myapp.generate import TARGETS, USERS
from myapp.logs import TIME_FORMAT

Entry = tuple[str, str, str]  # (status, user, ip)


def normal_entry(rng: random.Random) -> Entry:
    """One everyday login. Each user has a fixed IP and fails about 5% of the time."""
    user = rng.choice(USERS)
    status = "FAILED" if rng.random() < 0.05 else "SUCCESS"
    return status, user, f"10.0.1.{USERS.index(user) + 10}"


def attack_entries(rng: random.Random) -> list[Entry]:
    """A burst of attack events from outside IPs."""
    roll = rng.random()
    if roll < 0.4:
        ip = f"203.0.113.{rng.randint(1, 254)}"
        burst = [("FAILED", "admin", ip)] * 8
        if rng.random() < 0.5:
            burst.append(("SUCCESS", "admin", ip))  # the attacker got in
        return burst
    if roll < 0.7:
        ip = f"203.0.113.{rng.randint(1, 254)}"
        return [("FAILED", user, ip) for user in TARGETS]  # password spraying
    ends = rng.sample(range(1, 255), 3)  # one account, three different addresses
    return [("SUCCESS", "grace", f"192.0.2.{end}") for end in ends]


def entries(rng: random.Random, attack_every: int = 30) -> Iterator[Entry]:
    """An endless stream of events with an attack every `attack_every` events."""
    queue: list[Entry] = []
    tick = 0
    while True:
        tick += 1
        if tick % attack_every == 0:
            queue.extend(attack_entries(rng))
        yield queue.pop(0) if queue else normal_entry(rng)


def format_line(when: datetime, entry: Entry) -> str:
    status, user, ip = entry
    return f"{when.strftime(TIME_FORMAT)} {status} {user} {ip}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Write fake logins in real time.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/live.log"),
        help="log file to append to",
    )
    parser.add_argument("--interval", type=float, default=0.5, help="seconds per line")
    parser.add_argument(
        "--attack-every", type=int, default=30, help="events per attack"
    )
    parser.add_argument("--count", type=int, help="stop after this many lines")
    parser.add_argument("--seed", type=int, help="random seed")
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    stream = entries(random.Random(args.seed), args.attack_every)
    print(f"Writing to {args.output} every {args.interval}s (press Ctrl+C to stop)")
    written = 0
    try:
        with open(args.output, "a", encoding="utf-8") as f:
            for entry in islice(stream, args.count):
                f.write(format_line(datetime.now(), entry) + "\n")
                f.flush()  # make the line visible to the monitor right away
                written += 1
                time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    print(f"Wrote {written} lines.")


if __name__ == "__main__":
    main()
