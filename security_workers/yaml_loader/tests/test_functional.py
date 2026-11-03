from worker import load_config


def test_mapping() -> None:
    assert load_config("name: acv\nport: 8080\n") == {"name": "acv", "port": 8080}


def test_invalid() -> None:
    try:
        load_config("- one\n- two\n")
    except ValueError:
        return
    raise AssertionError("expected ValueError")
