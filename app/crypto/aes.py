# app/crypto/aes.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os, base64

BLOCK_SIZE = 128  # bits (for PKCS7)

def pkcs7_pad(data: bytes) -> bytes:
    padder = sym_padding.PKCS7(BLOCK_SIZE).padder()
    return padder.update(data) + padder.finalize()

def pkcs7_unpad(padded: bytes) -> bytes:
    unpadder = sym_padding.PKCS7(BLOCK_SIZE).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def aes_cbc_encrypt(plaintext: bytes, key: bytes) -> (str, str): # type: ignore
    """
    returns (iv_b64, ct_b64)
    key must be 16 bytes (AES-128)
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = pkcs7_pad(plaintext)
    ct = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv).decode(), base64.b64encode(ct).decode()

def aes_cbc_decrypt(iv_b64: str, ct_b64: str, key: bytes) -> bytes:
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    return pkcs7_unpad(padded)
