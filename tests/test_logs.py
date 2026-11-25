from datetime import datetime

import pytest

from myapp.logs import LoginEvent, parse_line


def test_parse_valid_line():
    event = parse_line("2026-11-25 09:15:02 FAILED admin 10.0.0.5")
    assert event == LoginEvent(
        datetime(2026, 11, 25, 9, 15, 2), False, "admin", "10.0.0.5"
    )


@pytest.mark.parametrize(
    "line",
    [
        "",
        "garbage",
        "2026-13-45 09:15:02 FAILED admin 10.0.0.5",
        "2026-11-25 09:15:02 MAYBE admin 10.0.0.5",
    ],
)
def test_bad_lines_return_none(line):
    assert parse_line(line) is None
