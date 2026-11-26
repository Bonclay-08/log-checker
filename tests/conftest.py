import pytest

from myapp.web import app


@pytest.fixture(autouse=True)
def temp_db(tmp_path):
    """Point the web app at a throwaway database for every test."""
    app.config["DB_PATH"] = tmp_path / "test.db"
