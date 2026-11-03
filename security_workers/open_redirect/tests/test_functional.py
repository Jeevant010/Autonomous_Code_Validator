from worker import next_url


def test_default() -> None:
    assert next_url(None) == "/"


def test_local_path() -> None:
    assert next_url("/dashboard") == "/dashboard"


def test_allowed_host() -> None:
    assert next_url("https://app.local/home") == "https://app.local/home"
