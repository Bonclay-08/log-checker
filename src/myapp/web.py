"""Web dashboard for the login log analyzer."""

from collections import Counter
from pathlib import Path
from typing import Any

from flask import Flask, render_template_string, request

from myapp.detect import run_all
from myapp.logs import parse_line
from myapp.report import build_report, failures_per_ip

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB upload limit
SAMPLE = Path(__file__).resolve().parents[2] / "data" / "sample.log"

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login Log Analyzer</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;background:#f2f5f9;color:#14213d}
main{max-width:860px;margin:0 auto;padding:24px 16px 48px}
h1{margin:0 0 4px}
.card{background:#fff;border:1px solid #d6dde8;border-radius:8px;padding:16px;
margin-top:16px}
.stats{display:flex;gap:12px;flex-wrap:wrap}
.stat{flex:1;min-width:130px}
.stat b{display:block;font-size:1.8rem}
.row{display:flex;align-items:center;gap:10px;margin:6px 0}
.label{width:110px;font-family:monospace}
.track{flex:1;background:#e6ecf4;border-radius:4px}
.bar{background:#306998;color:#fff;font-size:.8rem;padding:2px 6px;
border-radius:4px;min-width:26px;box-sizing:border-box}
.hours .bar{background:#b45309}
table{width:100%;border-collapse:collapse}
td,th{text-align:left;padding:8px;border-bottom:1px solid #d6dde8}
.tag{padding:2px 8px;border-radius:10px;background:#ffd43b;color:#3d3000;
font-size:.85rem}
.err{color:#b00020}
button{padding:8px 14px;margin-right:6px;cursor:pointer}
</style>
</head>
<body>
<main>
<h1>Login Log Analyzer</h1>
<p>Upload a log file to see failed logins and detected attacks.</p>
<div class="card">
<form method="post" enctype="multipart/form-data">
<input type="file" name="logfile">
<button type="submit">Analyze</button>
<button type="submit" name="sample" value="1">Use sample log</button>
</form>
{% if error %}<p class="err">{{ error }}</p>{% endif %}
</div>
{% if report %}
<div class="card stats">
<div class="stat"><b>{{ report.total_events }}</b>events</div>
<div class="stat"><b>{{ report.succeeded }}</b>successful</div>
<div class="stat"><b>{{ report.failed }}</b>failed</div>
<div class="stat"><b>{{ report.alerts|length }}</b>alerts</div>
</div>
<div class="card">
<h2>Alerts</h2>
{% if report.alerts %}
<table>
<tr><th>Type</th><th>IP address</th><th>Detail</th></tr>
{% for a in report.alerts %}
<tr><td><span class="tag">{{ a.kind }}</span></td><td>{{ a.ip }}</td>
<td>{{ a.detail }}</td></tr>
{% endfor %}
</table>
{% else %}<p>No alerts found.</p>{% endif %}
</div>
<div class="card">
<h2>Failed logins per IP</h2>
{% for o in offenders %}
<div class="row"><span class="label">{{ o.label }}</span>
<div class="track"><div class="bar" style="width:{{ o.pct }}%">{{ o.count }}</div>
</div></div>
{% else %}<p>No failed logins.</p>{% endfor %}
</div>
<div class="card hours">
<h2>Failed logins by hour</h2>
{% for h in hours %}
<div class="row"><span class="label">{{ h.label }}</span>
<div class="track"><div class="bar" style="width:{{ h.pct }}%">{{ h.count }}</div>
</div></div>
{% else %}<p>No failed logins.</p>{% endfor %}
</div>
{% endif %}
</main>
</body>
</html>
"""


def bars(counts: Counter[str], by_count: bool = True) -> list[dict[str, Any]]:
    """Turn counts into rows with a bar width in percent."""
    items = counts.most_common() if by_count else sorted(counts.items())
    top = max(counts.values(), default=1)
    return [
        {"label": label, "count": n, "pct": round(n / top * 100)} for label, n in items
    ]


def analyze(text: str) -> dict[str, Any]:
    """Parse log text and build everything the page needs."""
    events = sorted(
        (e for e in map(parse_line, text.splitlines()) if e is not None),
        key=lambda e: e.timestamp,
    )
    alerts = run_all(events)
    by_hour = Counter(e.timestamp.strftime("%H:00") for e in events if not e.success)
    return {
        "report": build_report(events, alerts),
        "offenders": bars(failures_per_ip(events)),
        "hours": bars(by_hour, by_count=False),
    }


@app.route("/", methods=["GET", "POST"])
def index() -> str:
    if request.method == "GET":
        return render_template_string(PAGE, report=None, error=None)
    if "sample" in request.form:
        text = SAMPLE.read_text(encoding="utf-8")
    else:
        upload = request.files.get("logfile")
        if upload is None or not upload.filename:
            message = "Choose a log file first."
            return render_template_string(PAGE, report=None, error=message)
        text = upload.read().decode("utf-8", errors="replace")
    return render_template_string(PAGE, error=None, **analyze(text))


def main() -> None:
    app.run(host="127.0.0.1", port=5000)


if __name__ == "__main__":
    main()
