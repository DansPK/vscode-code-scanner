import hashlib


def hash_password(password):
    # Planted problem: MD5 for passwords
    return hashlib.md5(password.encode()).hexdigest()
