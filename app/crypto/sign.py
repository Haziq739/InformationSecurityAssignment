# app/crypto/sign.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import base64
from cryptography import x509

def load_private_key(path: str, password: bytes = None) -> rsa.RSAPrivateKey:
    with open(path, "rb") as f:
        key_data = f.read()
    return serialization.load_pem_private_key(key_data, password=password, backend=default_backend())

def load_public_key(path: str) -> rsa.RSAPublicKey:
    """Load a raw PEM public key"""
    with open(path, "rb") as f:
        key_data = f.read()
    return serialization.load_pem_public_key(key_data, backend=default_backend())

def load_public_key_from_cert(cert_path: str) -> rsa.RSAPublicKey:
    """Extract public key from a certificate (PEM .crt)"""
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data)
    return cert.public_key()

def sign_message(private_key: rsa.RSAPrivateKey, message: bytes) -> str:
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_signature(public_key: rsa.RSAPublicKey, message: bytes, signature_b64: str) -> bool:
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
