from myapp.web import app


def test_home_page_loads():
    client = app.test_client()
    assert client.get("/").status_code == 200


def test_sample_analysis_shows_alerts():
    client = app.test_client()
    response = client.post("/", data={"sample": "1"})
    assert b"brute_force" in response.data
