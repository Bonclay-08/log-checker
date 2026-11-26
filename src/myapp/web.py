"""Web dashboard for the login log analyzer."""

from collections import Counter
from contextlib import closing
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template_string, request

from myapp.analysis import (
    failures_by_hour,
    to_frame,
    top_targeted_users,
    unusual_hours,
)
from myapp.db import connect, list_uploads, repeat_offenders, save_upload
from myapp.detect import run_all
from myapp.livefeed import LiveFeed
from myapp.logs import parse_line
from myapp.report import build_report, failures_per_ip

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB upload limit
SAMPLE = Path(__file__).resolve().parents[2] / "data" / "sample.log"
app.config["DB_PATH"] = SAMPLE.parent / "analyzer.db"
LIVE_LOG = SAMPLE.parent / "live.log"
feed = LiveFeed()

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
.chart{display:flex;align-items:stretch;gap:3px;height:190px;margin-top:8px}
.col{flex:1;min-width:0;display:flex;flex-direction:column;align-items:center}
.col .n{font-size:.7rem;height:14px}
.col .well{flex:1;width:100%;display:flex;align-items:flex-end}
.col .v{width:100%;background:#306998;border-radius:3px 3px 0 0;min-height:2px}
.col.hot .v{background:#c0392b}
.col .h{font-size:.7rem;color:#5a6678;height:14px}
.note{color:#5a6678;margin:10px 0 0}
.note b{color:#c0392b}
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
<p>Upload a log file to see failed logins and detected attacks, or
<a href="/live">watch a log live</a>.</p>
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
<h2>Failed logins by hour</h2>
<div class="chart">
{% for h in hours %}
<div class="col{% if h.hot %} hot{% endif %}"
title="{{ h.hour }}:00 - {{ h.count }} failed">
<span class="n">{% if h.count %}{{ h.count }}{% endif %}</span>
<div class="well"><div class="v" style="height:{{ h.pct }}%"></div></div>
<span class="h">{{ h.hour }}</span>
</div>
{% endfor %}
</div>
{% if hot_hours %}
<p class="note">Unusual hours (red): <b>{{ hot_hours|join(", ") }}</b>.
These hours have far more failures than the daily average.</p>
{% else %}<p class="note">No unusual hours found.</p>{% endif %}
</div>
<div class="card">
<h2>Failed logins per IP</h2>
{% for o in offenders %}
<div class="row"><span class="label">{{ o.label }}</span>
<div class="track"><div class="bar" style="width:{{ o.pct }}%">{{ o.count }}</div>
</div></div>
{% else %}<p>No failed logins.</p>{% endfor %}
</div>
<div class="card">
<h2>Most targeted accounts</h2>
{% for u in users %}
<div class="row"><span class="label">{{ u.label }}</span>
<div class="track"><div class="bar" style="width:{{ u.pct }}%">{{ u.count }}</div>
</div></div>
{% else %}<p>No failed logins.</p>{% endfor %}
</div>
{% endif %}
{% if history %}
<div class="card">
<h2>Upload history</h2>
<table>
<tr><th>When</th><th>File</th><th>Events</th><th>Failed</th><th>Alerts</th></tr>
{% for u in history %}
<tr><td>{{ u.uploaded_at }}</td><td>{{ u.name }}</td><td>{{ u.total_events }}</td>
<td>{{ u.failed }}</td><td>{{ u.alert_count }}</td></tr>
{% endfor %}
</table>
</div>
{% endif %}
{% if repeat %}
<div class="card">
<h2>Repeat offenders</h2>
<p class="note">IP addresses that triggered alerts in more than one upload.</p>
<table>
<tr><th>IP address</th><th>Uploads</th><th>Alerts</th></tr>
{% for r in repeat %}
<tr><td>{{ r.ip }}</td><td>{{ r.uploads }}</td><td>{{ r.alerts }}</td></tr>
{% endfor %}
</table>
</div>
{% endif %}
</main>
</body>
</html>
"""


def bars(counts: Counter[str]) -> list[dict[str, Any]]:
    """Turn counts into rows with a bar width in percent, biggest first."""
    top = max(counts.values(), default=1)
    return [
        {"label": label, "count": n, "pct": round(n / top * 100)}
        for label, n in counts.most_common()
    ]


def analyze(text: str) -> dict[str, Any]:
    """Parse log text and build everything the page needs."""
    events = sorted(
        (e for e in map(parse_line, text.splitlines()) if e is not None),
        key=lambda e: e.timestamp,
    )
    alerts = run_all(events)
    df = to_frame(events)

    hourly = failures_by_hour(df)
    flagged = {int(h) for h in unusual_hours(hourly).index}
    tallest = max(int(hourly.max()), 1)
    hours = [
        {
            "hour": f"{hour:02d}",
            "count": int(count),
            "pct": round(int(count) / tallest * 100),
            "hot": int(hour) in flagged,
        }
        for hour, count in hourly.items()
    ]

    targeted = Counter({str(u): int(n) for u, n in top_targeted_users(df).items()})
    return {
        "report": build_report(events, alerts),
        "offenders": bars(failures_per_ip(events)),
        "hours": hours,
        "hot_hours": [f"{h:02d}:00" for h in sorted(flagged)],
        "users": bars(targeted),
    }


def history() -> dict[str, Any]:
    """Past uploads and repeat offenders, read from the database."""
    with closing(connect(app.config["DB_PATH"])) as conn:
        return {
            "history": list_uploads(conn),
            "repeat": repeat_offenders(conn),
        }


@app.route("/", methods=["GET", "POST"])
def index() -> str:
    if request.method == "GET":
        return render_template_string(PAGE, report=None, error=None, **history())
    if "sample" in request.form:
        name = SAMPLE.name
        text = SAMPLE.read_text(encoding="utf-8")
    else:
        upload = request.files.get("logfile")
        if upload is None or not upload.filename:
            return render_template_string(
                PAGE, report=None, error="Choose a log file first.", **history()
            )
        name = upload.filename
        text = upload.read().decode("utf-8", errors="replace")
    result = analyze(text)
    with closing(connect(app.config["DB_PATH"])) as conn:
        save_upload(conn, name, result["report"])
    return render_template_string(PAGE, error=None, **result, **history())


LIVE_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Live Monitor</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;background:#f2f5f9;color:#14213d}
main{max-width:860px;margin:0 auto;padding:24px 16px 48px}
h1{margin:0 0 4px}
.card{background:#fff;border:1px solid #d6dde8;border-radius:8px;padding:16px;
margin-top:16px}
.stats{display:flex;gap:12px;flex-wrap:wrap}
.stat{flex:1;min-width:130px}
.stat b{display:block;font-size:1.8rem}
.status{display:flex;align-items:center;gap:8px;color:#5a6678}
.dot{width:10px;height:10px;border-radius:50%;background:#2e9e5b}
.dot.off{background:#b00020}
table{width:100%;border-collapse:collapse}
td,th{text-align:left;padding:8px;border-bottom:1px solid #d6dde8}
tr.new td{background:#fff3c4}
.tag{padding:2px 8px;border-radius:10px;background:#ffd43b;color:#3d3000;
font-size:.85rem}
code{background:#e6ecf4;padding:2px 6px;border-radius:4px}
</style>
</head>
<body>
<main>
<h1>Live Monitor</h1>
<p><a href="/">Back to the upload page</a></p>
<div class="card status"><span class="dot" id="dot"></span>
<span>Watching <code id="path">...</code>, updating every 2 seconds</span></div>
<div class="card stats">
<div class="stat"><b id="lines">0</b>new lines read</div>
<div class="stat"><b id="count">0</b>alerts</div>
</div>
<div class="card">
<h2>Alerts</h2>
<p id="empty">No alerts yet. In another terminal, run
<code>python -m myapp.simulate</code> to generate live traffic.</p>
<table id="table" hidden>
<thead><tr><th>Time</th><th>Type</th><th>IP address</th><th>Detail</th></tr></thead>
<tbody id="rows"></tbody>
</table>
</div>
</main>
<script>
var seen = new Set();
function cell(text) {
  var td = document.createElement("td");
  td.textContent = text;  // textContent keeps log data from running as HTML
  return td;
}
async function refresh() {
  var dot = document.getElementById("dot");
  try {
    var response = await fetch("/api/live");
    var data = await response.json();
    document.getElementById("path").textContent = data.watching || "nothing";
    document.getElementById("lines").textContent = data.lines;
    document.getElementById("count").textContent = data.alerts.length;
    var rows = document.getElementById("rows");
    rows.replaceChildren();
    var first = seen.size === 0;
    data.alerts.forEach(function (a) {
      var key = a.time + "|" + a.kind + "|" + a.ip;
      var tr = document.createElement("tr");
      if (!first && !seen.has(key)) { tr.className = "new"; }
      seen.add(key);
      var type = document.createElement("td");
      var tag = document.createElement("span");
      tag.className = "tag";
      tag.textContent = a.kind;
      type.appendChild(tag);
      tr.appendChild(cell(a.time));
      tr.appendChild(type);
      tr.appendChild(cell(a.ip));
      tr.appendChild(cell(a.detail));
      rows.appendChild(tr);
    });
    var any = data.alerts.length > 0;
    document.getElementById("table").hidden = !any;
    document.getElementById("empty").hidden = any;
    dot.className = "dot";
  } catch (error) {
    dot.className = "dot off";
  }
}
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""


@app.route("/live")
def live() -> str:
    return LIVE_PAGE


@app.route("/api/live")
def api_live() -> Response:
    return jsonify(feed.snapshot())


def main() -> None:
    feed.start(LIVE_LOG)
    app.run(host="127.0.0.1", port=5000)


if __name__ == "__main__":
    main()
