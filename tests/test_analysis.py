from myapp.analysis import (
    failures_by_hour,
    to_frame,
    top_targeted_users,
    unusual_hours,
)
from myapp.generate import generate
from myapp.logs import parse_line


def make_frame(count=500, seed=42):
    events = [parse_line(line) for line in generate(count, seed)]
    return to_frame([e for e in events if e is not None])


def test_frame_has_one_row_per_event():
    df = make_frame()
    assert len(df) == len(generate(500))
    assert list(df.columns) == ["timestamp", "success", "user", "ip"]


def test_failures_by_hour_covers_all_24_hours():
    df = make_frame()
    hourly = failures_by_hour(df)
    assert len(hourly) == 24
    assert hourly.sum() == (~df["success"]).sum()


def test_attack_hours_are_flagged_as_unusual():
    hourly = failures_by_hour(make_frame())
    flagged = list(unusual_hours(hourly).index)
    assert 3 in flagged
    assert 22 in flagged


def test_admin_is_the_most_targeted_account():
    assert top_targeted_users(make_frame()).index[0] == "admin"


def test_empty_log_is_handled():
    df = to_frame([])
    hourly = failures_by_hour(df)
    assert hourly.sum() == 0
    assert unusual_hours(hourly).empty
    assert top_targeted_users(df).empty
