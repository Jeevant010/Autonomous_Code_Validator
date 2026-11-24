"""Behaviour that must keep working after the CVE-2020-14343 fix.

Safe loading and the documented ``unsafe_load`` escape hatch must be unchanged.
A patch that "fixes" the CVE by breaking YAML parsing is rejected.
"""

from __future__ import annotations

import yaml


def test_safe_load_mapping() -> None:
    assert yaml.safe_load("a: 1\nb: [2, 3]\n") == {"a": 1, "b": [2, 3]}


def test_safe_load_scalars() -> None:
    assert yaml.safe_load("42") == 42
    assert yaml.safe_load("hello") == "hello"
    assert yaml.safe_load("true") is True


def test_safe_load_nested() -> None:
    document = "root:\n  child:\n    - one\n    - two\n"
    assert yaml.safe_load(document) == {"root": {"child": ["one", "two"]}}


def test_full_load_still_reads_plain_data() -> None:
    # full_load is documented to handle normal Python data. It must keep doing so.
    assert yaml.full_load("a: 1\nb: 2\n") == {"a": 1, "b": 2}


def test_safe_dump_round_trip() -> None:
    data = {"x": [1, 2], "y": {"z": "text"}}
    assert yaml.safe_load(yaml.safe_dump(data)) == data


def test_safe_load_rejects_dangerous_tags() -> None:
    import pytest

    with pytest.raises(yaml.YAMLError):
        yaml.safe_load("!!python/object/apply:os.system ['echo hi']")
