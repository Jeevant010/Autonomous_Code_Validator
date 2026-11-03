from worker import lookup


def test_alice() -> None:
    assert lookup("alice") == [("alice", "admin")]


def test_bob() -> None:
    assert lookup("bob") == [("bob", "user")]


def test_missing() -> None:
    assert lookup("nobody") == []
