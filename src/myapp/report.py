"""Build text and JSON reports."""

import json
from collections import Counter
from dataclasses import asdict
from typing import Any

from myapp.detect import Alert
from myapp.logs import LoginEvent
from myapp.stats import summary


def failures_per_ip(events: list[LoginEvent]) -> Counter[str]:
    return Counter(e.ip for e in events if not e.success)


def build_report(events: list[LoginEvent], alerts: list[Alert]) -> dict[str, Any]:
    failures = failures_per_ip(events)
    failed = sum(failures.values())
    report: dict[str, Any] = {
        "total_events": len(events),
        "failed": failed,
        "succeeded": len(events) - failed,
        "alerts": [asdict(alert) for alert in alerts],
    }
    if failures:
        report["failures_per_ip"] = summary([float(n) for n in failures.values()])
        report["top_offenders"] = failures.most_common(3)
    return report


def to_text(report: dict[str, Any]) -> str:
    lines = [
        f"Events: {report['total_events']} "
        f"({report['succeeded']} ok, {report['failed']} failed)"
    ]
    if "top_offenders" in report:
        lines.append("Top offenders:")
        for ip, count in report["top_offenders"]:
            lines.append(f"  {ip}: {count} failures")
    if report["alerts"]:
        lines.append("Alerts:")
        for alert in report["alerts"]:
            lines.append(f"  [{alert['kind']}] {alert['ip']}: {alert['detail']}")
    else:
        lines.append("No alerts.")
    return "\n".join(lines)


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2)
