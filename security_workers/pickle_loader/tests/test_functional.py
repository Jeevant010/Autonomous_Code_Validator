import pickle

from worker import load_profile


def test_profile() -> None:
    assert load_profile(pickle.dumps({"name": "alice"})) == {"name": "alice"}


def test_invalid() -> None:
    try:
        load_profile(b"not-a-pickle")
    except Exception:
        return
    raise AssertionError("expected an error")
