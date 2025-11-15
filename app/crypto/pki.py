from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from datetime import datetime
import os

CERTS_DIR = "certs"

def load_certificate(cert_path: str) -> x509.Certificate:
    """Load a certificate from a PEM file."""
    with open(cert_path, "rb") as f:
        cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)
    return cert

def load_private_key(key_path: str):
    """Load a private key from a PEM file."""
    with open(key_path, "rb") as f:
        key_data = f.read()
        private_key = serialization.load_pem_private_key(key_data, password=None)
    return private_key

def validate_certificate(cert: x509.Certificate, ca_cert: x509.Certificate, expected_cn: str) -> bool:
    """
    Validate that a certificate:
    1. Is signed by the provided CA
    2. Is within its validity period
    3. Matches the expected Common Name (CN)
    """
    # 1. Verify signature with CA public key
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        print(f"Certificate signature verification failed: {e}")
        return False

    # 2. Check validity period
    now = datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        print("Certificate is expired or not yet valid")
        return False

    # 3. Check CN (Common Name)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if cn != expected_cn:
        print(f"Certificate CN mismatch: expected {expected_cn}, got {cn}")
        return False

    # Certificate passed all checks
    return True

# Example helper to load CA, server, and client certs
def load_and_validate_entity(entity_name: str) -> x509.Certificate:
    ca_cert = load_certificate(os.path.join(CERTS_DIR, "root_ca.crt"))
    entity_cert = load_certificate(os.path.join(CERTS_DIR, f"{entity_name}.crt"))
    if validate_certificate(entity_cert, ca_cert, expected_cn=entity_name):
        print(f"{entity_name} certificate is valid")
        return entity_cert
    else:
        raise ValueError(f"{entity_name} certificate validation failed")
