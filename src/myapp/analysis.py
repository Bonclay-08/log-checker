"""Analyze login events with pandas."""

import argparse
from pathlib import Path

import pandas as pd

from myapp.logs import LoginEvent, read_log


def to_frame(events: list[LoginEvent]) -> pd.DataFrame:
    """Turn events into a table with one row per login attempt."""
    df = pd.DataFrame(
        {
            "timestamp": [e.timestamp for e in events],
            "success": [e.success for e in events],
            "user": [e.user for e in events],
            "ip": [e.ip for e in events],
        }
    )
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["success"] = df["success"].astype(bool)
    return df


def failures_by_hour(df: pd.DataFrame) -> pd.Series:
    """Failed logins for each hour of the day (0-23), including quiet hours."""
    failed = df[~df["success"]]
    counts = failed["timestamp"].dt.hour.value_counts()
    return counts.reindex(range(24), fill_value=0).sort_index()


def unusual_hours(hourly: pd.Series, z_threshold: float = 2.0) -> pd.Series:
    """Hours with failures far above the daily average.

    The z-score says how many standard deviations an hour is above the mean.
    """
    std = hourly.std(ddof=0)
    if std == 0:
        return hourly.iloc[0:0]
    z_scores = (hourly - hourly.mean()) / std
    return hourly[z_scores >= z_threshold]


def top_targeted_users(df: pd.DataFrame, n: int = 5) -> pd.Series:
    """The accounts with the most failed logins."""
    failed = df[~df["success"]]
    return failed["user"].value_counts().head(n)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze failures by hour.")
    parser.add_argument("logfile", type=Path, help="path to the log file")
    parser.add_argument("--z", type=float, default=2.0, help="z-score threshold")
    args = parser.parse_args()

    df = to_frame(read_log(args.logfile))
    hourly = failures_by_hour(df)

    print("Failed logins by hour:")
    for hour, count in hourly.items():
        print(f"  {hour:02d}:00  {count:3d}  {'#' * int(count)}")

    unusual = unusual_hours(hourly, args.z)
    print(f"\nUnusual hours (z-score of {args.z} or more):")
    if unusual.empty:
        print("  none")
    for hour, count in unusual.items():
        print(f"  {hour:02d}:00  {count} failures")

    print("\nMost targeted accounts:")
    for user, count in top_targeted_users(df).items():
        print(f"  {user}: {count}")


if __name__ == "__main__":
    main()
