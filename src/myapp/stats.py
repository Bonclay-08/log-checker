"""Small statistics helpers."""

import argparse


def average(nums: list[float]) -> float:
    """Return the mean of nums."""
    if not nums:
        raise ValueError("average() needs at least one number")
    return sum(nums) / len(nums)


def summary(nums: list[float]) -> dict[str, float]:
    """Return the main statistics for nums in one dictionary."""
    if not nums:
        raise ValueError("summary() needs at least one number")
    mean = average(nums)
    ordered = sorted(nums)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        middle = ordered[mid]
    else:
        middle = (ordered[mid - 1] + ordered[mid]) / 2
    variance = sum((x - mean) ** 2 for x in nums) / len(nums)
    return {
        "count": len(nums),
        "average": mean,
        "median": middle,
        "std_dev": variance**0.5,
        "min": min(nums),
        "max": max(nums),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize a list of numbers.")
    parser.add_argument("numbers", nargs="+", type=float)
    args = parser.parse_args()
    for name, value in summary(args.numbers).items():
        print(f"{name}: {value:g}")


if __name__ == "__main__":
    main()
