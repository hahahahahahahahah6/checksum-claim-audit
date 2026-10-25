import hashlib


def test_digest():
    assert hashlib.sha256(b"x").hexdigest()
