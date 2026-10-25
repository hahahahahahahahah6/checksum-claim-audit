import hashlib


def install(data, expected):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise ValueError("bad checksum")
    return True
