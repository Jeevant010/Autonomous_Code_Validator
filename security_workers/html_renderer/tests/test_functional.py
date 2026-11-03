from worker import render_comment


def test_plain_comment() -> None:
    output = render_comment("alice", "hello")
    assert "<article>" in output
    assert "alice" in output
    assert "hello" in output


def test_unicode_comment() -> None:
    output = render_comment("Renee", "cafe")
    assert "Renee" in output
    assert "cafe" in output
