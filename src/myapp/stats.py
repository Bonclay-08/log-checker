"""Small statistics helpers."""


def average(nums: list[float]) -> float:
    """Return the mean of nums.

    Raises:
        ValueError: if nums is empty.
    """
    if not nums:
        raise ValueError("average() needs at least one number")
    return sum(nums) / len(nums)


def main() -> None:
    print(average([2, 4, 6]))


if __name__ == "__main__":
    main()
