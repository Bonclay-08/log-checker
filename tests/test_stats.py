import pytest

from myapp.stats import average


def test_average_of_two_numbers():
    assert average([2, 4]) == 3


def test_average_of_single_number():
    assert average([5]) == 5


def test_average_of_empty_list_raises():
    with pytest.raises(ValueError):
        average([])
