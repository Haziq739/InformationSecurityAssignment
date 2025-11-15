from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def extract_public_key(cert_path, output_path):
    with open(cert_path, "rb") as f:
        cert_data = f.read()

    # Load X.509 certificate
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Extract public key
    pubkey = cert.public_key()

    # Save as PEM PUBLIC KEY
    pem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(output_path, "wb") as f:
        f.write(pem)

    print(f"[OK] Extracted public key → {output_path}")

if __name__ == "__main__":
    extract_public_key("certs/server.crt", "certs/server_pub.pem")
