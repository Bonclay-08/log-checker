"""Background live feed: watches a log file and keeps the recent alerts."""

import threading
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

from myapp.live import Monitor, follow


class LiveFeed:
    """Holds what the live page shows. A background thread fills it in."""

    def __init__(self, max_alerts: int = 50) -> None:
        self.monitor = Monitor()
        self.alerts: deque[dict[str, str]] = deque(maxlen=max_alerts)
        self.lines = 0
        self.path: Path | None = None
        self.lock = threading.Lock()  # the web server and the watcher share this data

    def handle(self, line: str) -> None:
        """Process one new log line, saving any new alerts (newest first)."""
        new = self.monitor.add(line)
        now = datetime.now().strftime("%H:%M:%S")
        with self.lock:
            self.lines += 1
            for alert in new:
                self.alerts.appendleft(
                    {
                        "time": now,
                        "kind": alert.kind,
                        "ip": alert.ip,
                        "detail": alert.detail,
                    }
                )

    def snapshot(self) -> dict[str, Any]:
        """A copy of the current state, safe to send to the browser."""
        with self.lock:
            return {
                "watching": str(self.path) if self.path else None,
                "lines": self.lines,
                "alerts": list(self.alerts),
            }

    def start(self, path: Path) -> None:
        """Start watching a log file in a background thread."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
        self.path = path
        threading.Thread(target=self._run, args=(path,), daemon=True).start()

    def _run(self, path: Path) -> None:
        for line in follow(path):
            self.handle(line)
