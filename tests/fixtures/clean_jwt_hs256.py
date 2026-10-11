"""Representative HMAC JWT usage; do not misclassify it as Shor-broken."""
import jwt

def sign(payload, secret):
    return jwt.encode(payload, secret, algorithm="HS256")
