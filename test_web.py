from io import BytesIO

from myapp.generate import generate
from myapp.web import app


def upload(client, text):
    data = {"logfile": (BytesIO(text.encode("utf-8")), "test.log")}
    return client.post("/", data=data, content_type="multipart/form-data")


def test_home_page_loads():
    client = app.test_client()
    assert client.get("/").status_code == 200


def test_sample_analysis_shows_alerts():
    client = app.test_client()
    response = client.post("/", data={"sample": "1"})
    assert b"brute_force" in response.data


def test_uploaded_log_shows_unusual_hours_in_red():
    client = app.test_client()
    response = upload(client, "\n".join(generate(500)))
    assert response.status_code == 200
    assert b'class="col hot"' in response.data
    assert b"03:00" in response.data


def test_upload_without_file_shows_error():
    client = app.test_client()
    response = client.post("/", data={}, content_type="multipart/form-data")
    assert b"Choose a log file first." in response.data


def test_empty_log_does_not_crash():
    client = app.test_client()
    assert upload(client, "").status_code == 200


def test_upload_is_saved_to_history():
    client = app.test_client()
    client.post("/", data={"sample": "1"})
    page = client.get("/")
    assert b"Upload history" in page.data
    assert b"sample.log" in page.data


def test_same_attackers_in_two_uploads_become_repeat_offenders():
    client = app.test_client()
    text = "\n".join(generate(500))
    upload(client, text)
    response = upload(client, text)
    assert b"Repeat offenders" in response.data
    assert b"203.0.113.5" in response.data
