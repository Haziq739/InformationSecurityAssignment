from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID
import cryptography.x509 as x509
from datetime import datetime, timedelta
import os

# Folder to save CA keys and certificate
CERTS_DIR = "certs"
os.makedirs(CERTS_DIR, exist_ok=True)

# 1. Generate RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# 2. Serialize and save private key (PEM format)
with open(os.path.join(CERTS_DIR, "root_ca.key"), "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # No passphrase for simplicity
    ))

# 3. Create self-signed X.509 certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MySecureChat"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"MyRootCA"),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.utcnow()
).not_valid_after(
    # Certificate valid for 10 years
    datetime.utcnow() + timedelta(days=3650)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True,
).sign(private_key, hashes.SHA256())

# 4. Serialize and save certificate (PEM format)
with open(os.path.join(CERTS_DIR, "root_ca.crt"), "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("Root CA generation complete. Files saved in 'certs/' folder:")
print("- root_ca.key (private key)")
print("- root_ca.crt (self-signed certificate)")
