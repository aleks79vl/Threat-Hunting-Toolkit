from src.utils.tshark_dependency import (
    find_tshark,
    is_tshark_available,
)


def test_find_tshark_returns_path():
    tshark_path = find_tshark()

    assert tshark_path is not None
    assert "tshark" in tshark_path.lower()


def test_tshark_is_available():
    assert is_tshark_available() is True