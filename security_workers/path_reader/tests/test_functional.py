from worker import read_note


def test_public_note() -> None:
    assert "public note" in read_note("notes.txt")


def test_nested_note() -> None:
    assert "nested note" in read_note("nested/note.txt")
