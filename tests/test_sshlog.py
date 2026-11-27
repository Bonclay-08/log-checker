from datetime import datetime
from pathlib import Path

import pytest

from myapp.detect import run_all
from myapp.logs import LoginEvent, parse_line, parse_ssh_line, read_log

SAMPLE = Path(__file__).resolve().parents[1] / "data" / "ssh_sample.log"


def ssh(message, stamp="Nov 26 09:15:04"):
    return f"{stamp} web01 sshd[2212]: {message}"


def test_failed_password_line():
    line = ssh("Failed password for root from 203.0.113.5 port 52120 ssh2")
    expected = LoginEvent(
        datetime(2026, 11, 26, 9, 15, 4), False, "root", "203.0.113.5"
    )
    assert parse_ssh_line(line, year=2026) == expected


def test_invalid_user_name_is_extracted():
    line = ssh("Failed password for invalid user admin from 1.2.3.4 port 22 ssh2")
    event = parse_ssh_line(line, year=2026)
    assert event is not None
    assert (event.user, event.ip, event.success) == ("admin", "1.2.3.4", False)


def test_accepted_password_line():
    line = ssh("Accepted password for grace from 10.0.0.12 port 50022 ssh2")
    event = parse_ssh_line(line, year=2026)
    assert event is not None
    assert (event.user, event.ip, event.success) == ("grace", "10.0.0.12", True)


def test_accepted_publickey_with_trailing_text():
    line = ssh("Accepted publickey for sam from 10.0.0.9 port 22 ssh2: RSA SHA256:x")
    event = parse_ssh_line(line, year=2026)
    assert event is not None
    assert event.success is True


def test_single_digit_day_is_padded_with_a_space():
    line = ssh("Failed password for root from 1.2.3.4 port 22 ssh2", "Nov  5 09:00:00")
    event = parse_ssh_line(line, year=2026)
    assert event is not None
    assert event.timestamp == datetime(2026, 11, 5, 9, 0, 0)


def test_iso_timestamp_format():
    line = (
        "2026-11-26T09:15:04.123456+00:00 web01 sshd[1]: "
        "Failed password for root from 1.2.3.4 port 22 ssh2"
    )
    event = parse_ssh_line(line)
    assert event is not None
    assert event.timestamp == datetime(2026, 11, 26, 9, 15, 4, 123456)


@pytest.mark.parametrize(
    "message",
    [
        "Invalid user admin from 1.2.3.4 port 22",
        "Received disconnect from 1.2.3.4 port 22:11: bye",
        "pam_unix(sshd:session): session opened for user root",
    ],
)
def test_other_sshd_messages_are_ignored(message):
    assert parse_ssh_line(ssh(message), year=2026) is None


def test_lines_from_other_programs_are_ignored():
    line = (
        "Nov 26 09:15:04 web01 cron[1]: Failed password for root from 1.2.3.4 port 22"
    )
    assert parse_ssh_line(line, year=2026) is None


def test_parse_line_understands_both_formats():
    simple = parse_line("2026-11-25 09:15:01 FAILED admin 10.0.0.5")
    ssh_event = parse_line(ssh("Failed password for root from 1.2.3.4 port 22 ssh2"))
    assert simple is not None
    assert ssh_event is not None
    assert simple.user == "admin"
    assert ssh_event.user == "root"


def test_sample_ssh_log_triggers_all_three_alerts():
    events = read_log(SAMPLE)
    kinds = {alert.kind for alert in run_all(events)}
    assert kinds == {"brute_force", "password_spraying", "success_after_failures"}
