from Crypto.PublicKey import RSA

def generate_rsa_key():
    key = RSA.generate(2048)
    return key

def export_public_key(key):
    return key.publickey().export_key()
