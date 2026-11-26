from contextlib import closing

from myapp.db import connect, get_alerts, list_uploads, repeat_offenders, save_upload


def make_report(*alerts):
    return {
        "total_events": 15,
        "failed": 4,
        "alerts": [{"kind": kind, "ip": ip, "detail": "test"} for kind, ip in alerts],
    }


def test_save_and_list_uploads(tmp_path):
    with closing(connect(tmp_path / "t.db")) as conn:
        first = save_upload(conn, "a.log", make_report(("brute_force", "1.1.1.1")))
        second = save_upload(conn, "b.log", make_report())
        uploads = list_uploads(conn)
    assert [u["name"] for u in uploads] == ["b.log", "a.log"]
    assert uploads[1]["alert_count"] == 1
    assert second > first


def test_alerts_are_saved_with_their_upload(tmp_path):
    with closing(connect(tmp_path / "t.db")) as conn:
        upload_id = save_upload(conn, "a.log", make_report(("brute_force", "1.1.1.1")))
        alerts = get_alerts(conn, upload_id)
    assert alerts == [{"kind": "brute_force", "ip": "1.1.1.1", "detail": "test"}]


def test_repeat_offenders_need_two_different_uploads(tmp_path):
    with closing(connect(tmp_path / "t.db")) as conn:
        save_upload(conn, "a.log", make_report(("brute_force", "1.1.1.1")))
        save_upload(conn, "b.log", make_report(("brute_force", "1.1.1.1")))
        save_upload(conn, "c.log", make_report(("brute_force", "2.2.2.2")))
        offenders = repeat_offenders(conn)
    assert [o["ip"] for o in offenders] == ["1.1.1.1"]
    assert offenders[0]["uploads"] == 2


def test_hostile_file_name_cannot_inject_sql(tmp_path):
    evil = "x'); DROP TABLE uploads; --"
    with closing(connect(tmp_path / "t.db")) as conn:
        save_upload(conn, evil, make_report())
        uploads = list_uploads(conn)
    assert uploads[0]["name"] == evil
