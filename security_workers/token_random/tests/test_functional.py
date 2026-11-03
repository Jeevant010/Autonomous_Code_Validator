from worker import reset_token


def test_length() -> None:
    assert len(reset_token(24)) == 24


def test_charset() -> None:
    assert reset_token(24).isalnum()


def test_two_tokens_differ() -> None:
    assert reset_token(24) != reset_token(24)
