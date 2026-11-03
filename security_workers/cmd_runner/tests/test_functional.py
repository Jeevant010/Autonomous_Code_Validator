from worker import run_echo


def test_echo() -> None:
    assert run_echo("hello") == "hello\n"


def test_spaces() -> None:
    assert run_echo("hello world") == "hello world\n"
