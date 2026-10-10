"""Representative PyJWT usage with a quantum-vulnerable asymmetric algorithm."""
import jwt

def sign(payload, private_key):
    return jwt.encode(payload, private_key, algorithm="RS256")
