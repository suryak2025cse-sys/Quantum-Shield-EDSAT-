from cryptography.hazmat.primitives.asymmetric import rsa, ec
import hashlib

def generate_signing_key():
    # Quantum-vulnerable: RSA key generation
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def generate_ecdsa_key():
    # Quantum-vulnerable: ECDSA
    return ec.generate_private_key(ec.SECP256R1())

def legacy_hash(data):
    return hashlib.md5(data).hexdigest()

def legacy_checksum(data):
    return hashlib.sha1(data).hexdigest()
