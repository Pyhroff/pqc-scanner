import hashlib

def bad_hash(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def also_bad(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

def via_new(data: bytes) -> str:
    return hashlib.new("md5", data).hexdigest()
