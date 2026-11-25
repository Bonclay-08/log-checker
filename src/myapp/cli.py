"""Command-line interface."""

import argparse
import sys
from pathlib import Path

from myapp.detect import run_all
from myapp.logs import read_log
from myapp.report import build_report, to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="myapp", description="Analyze login logs.")
    parser.add_argument("logfile", type=Path, help="path to the log file")
    parser.add_argument("--json", action="store_true", help="print JSON output")
    parser.add_argument(
        "--max-failures", type=int, default=5, help="failures that count as brute force"
    )
    parser.add_argument("--window", type=int, default=60, help="window in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        events = read_log(args.logfile)
    except FileNotFoundError:
        print(f"File not found: {args.logfile}", file=sys.stderr)
        return 1
    alerts = run_all(events, args.max_failures, args.window)
    report = build_report(events, alerts)
    print(to_json(report) if args.json else to_text(report))
    return 2 if alerts else 0
