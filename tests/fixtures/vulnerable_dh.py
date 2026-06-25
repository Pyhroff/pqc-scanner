from cryptography.hazmat.primitives.asymmetric import dh

def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    return parameters

def dh_private_key(parameters):
    return parameters.generate_private_key()
