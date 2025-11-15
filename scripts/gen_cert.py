from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID, DNSName
import cryptography.x509 as x509
from cryptography.x509.oid import ExtensionOID
from datetime import datetime, timedelta
import os

# Folder to save generated keys and certificates
CERTS_DIR = "certs"
os.makedirs(CERTS_DIR, exist_ok=True)

# Load Root CA private key and certificate
with open(os.path.join(CERTS_DIR, "root_ca.key"), "rb") as f:
    root_key = serialization.load_pem_private_key(f.read(), password=None)

with open(os.path.join(CERTS_DIR, "root_ca.crt"), "rb") as f:
    root_cert = x509.load_pem_x509_certificate(f.read())

def generate_entity_cert(name: str):
    """Generate RSA key pair and X.509 cert signed by Root CA"""
    # 1. Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # 2. Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MySecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

    # 3. Build certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        root_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=1825)  # 5 years validity
    ).add_extension(
        x509.SubjectAlternativeName([DNSName(name)]),
        critical=False
    ).sign(root_key, hashes.SHA256())

    # 4. Save private key and certificate
    key_path = os.path.join(CERTS_DIR, f"{name}.key")
    cert_path = os.path.join(CERTS_DIR, f"{name}.crt")

    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"{name} key and certificate generated:")
    print(f"- {key_path}")
    print(f"- {cert_path}")

# Generate server and client certificates
generate_entity_cert("server")
generate_entity_cert("client")
