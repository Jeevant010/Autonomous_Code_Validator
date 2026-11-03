import os

os.environ["ACV_TOKEN_SECRET"] = "test-secret-value-123456"

from worker import sign, verify


def test_roundtrip() -> None:
    value = "user:42"
    assert verify(value, sign(value))


def test_tamper() -> None:
    value = "user:42"
    assert not verify("user:43", sign(value))
