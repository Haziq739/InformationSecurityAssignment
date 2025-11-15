# app/crypto/dh.py
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
import math

def generate_parameters(key_size=2048):
    params = dh.generate_parameters(generator=2, key_size=key_size)
    nums = params.parameter_numbers()
    return nums.p, nums.g

def generate_private_and_public(p: int, g: int):
    # Build parameters from p,g and generate private key & public integer
    params = dh.DHParameterNumbers(p, g).parameters()
    priv = params.generate_private_key()
    pub = priv.public_key().public_numbers().y
    return priv, pub

def compute_shared_secret(private_key, peer_public_int: int, p: int, g: int) -> bytes:
    """
    private_key: a DH private key object created from parameters
    peer_public_int: integer (y) of peer's public key
    returns shared key bytes
    """
    peer_pub_nums = dh.DHPublicNumbers(peer_public_int, dh.DHParameterNumbers(p, g))
    peer_pub_key = peer_pub_nums.public_key()
    shared = private_key.exchange(peer_pub_key)  # returns bytes
    # shared is already a byte-string; caller will SHA256 it and take first 16 bytes
    return shared
