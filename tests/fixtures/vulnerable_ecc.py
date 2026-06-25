from cryptography.hazmat.primitives.asymmetric import ec

def generate_ec_key():
    key = ec.generate_private_key(ec.SECP256R1())
    return key

def ecdh_exchange(private_key, peer_public_key):
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    shared = private_key.exchange(_ec.ECDH(), peer_public_key)
    return shared
