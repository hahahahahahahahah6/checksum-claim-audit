import hashlib


def install(data):
    return hashlib.sha256(data).hexdigest()
