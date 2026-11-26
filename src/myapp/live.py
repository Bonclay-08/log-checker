"""Watch a log file as it grows and raise alerts in real time."""

import argparse
import os
import time
from collections import deque
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

from myapp.detect import Alert, run_all
from myapp.logs import LoginEvent, parse_line


def follow(
    path: Path,
    poll_seconds: float = 0.5,
    from_start: bool = False,
    timeout: float | None = None,
) -> Iterator[str]:
    """Yield lines as they are added to a file, like `tail -f`.

    Skips what is already in the file unless from_start is True. Stops after
    `timeout` seconds without new data (None means keep watching forever).
    """
    with open(path, encoding="utf-8") as f:
        if not from_start:
            f.seek(0, os.SEEK_END)
        buffer = ""  # holds a half-written line until its newline arrives
        last_data = time.monotonic()
        while True:
            chunk = f.readline()
            if chunk:
                last_data = time.monotonic()
                buffer += chunk
                if buffer.endswith("\n"):
                    yield buffer
                    buffer = ""
                continue
            if timeout is not None and time.monotonic() - last_data > timeout:
                return
            time.sleep(poll_seconds)


class Monitor:
    """Keep a sliding window of recent events and report each new alert once.

    An alert is reported when it first appears. If it later drops out of the
    window and the same attack starts again, it is reported again.
    """

    def __init__(
        self,
        window_minutes: int = 15,
        max_failures: int = 5,
        window_seconds: int = 60,
    ) -> None:
        self.window = timedelta(minutes=window_minutes)
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.events: deque[LoginEvent] = deque()
        self.active: set[tuple[str, str]] = set()

    def add(self, line: str) -> list[Alert]:
        """Process one log line and return any alerts that are new."""
        event = parse_line(line)
        if event is None:
            return []
        self.events.append(event)
        cutoff = event.timestamp - self.window
        while self.events and self.events[0].timestamp < cutoff:
            self.events.popleft()

        current = run_all(list(self.events), self.max_failures, self.window_seconds)
        keys = {(a.kind, a.ip) for a in current}
        new = [a for a in current if (a.kind, a.ip) not in self.active]
        self.active = keys
        return new


def main() -> None:
    parser = argparse.ArgumentParser(description="Watch a log and alert live.")
    parser.add_argument("logfile", type=Path, help="log file to watch")
    parser.add_argument(
        "--from-start", action="store_true", help="also read lines already in the file"
    )
    parser.add_argument("--max-failures", type=int, default=5, help="brute force limit")
    parser.add_argument("--window", type=int, default=60, help="seconds for that limit")
    args = parser.parse_args()

    args.logfile.parent.mkdir(parents=True, exist_ok=True)
    args.logfile.touch(exist_ok=True)
    monitor = Monitor(max_failures=args.max_failures, window_seconds=args.window)

    print(f"Watching {args.logfile} (press Ctrl+C to stop)")
    lines = 0
    try:
        for line in follow(args.logfile, from_start=args.from_start):
            lines += 1
            for alert in monitor.add(line):
                now = datetime.now().strftime("%H:%M:%S")
                print(f"[{now}] ALERT {alert.kind} from {alert.ip}: {alert.detail}")
    except KeyboardInterrupt:
        print(f"\nStopped after reading {lines} new lines.")


if __name__ == "__main__":
    main()
