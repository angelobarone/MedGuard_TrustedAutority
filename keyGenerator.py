from phe import paillier


def generate_key():
    public, private = paillier.generate_paillier_keypair()
    return public, private