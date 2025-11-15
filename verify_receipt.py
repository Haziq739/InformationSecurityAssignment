import json, hashlib
from app.crypto import sign
from cryptography import x509

def load_pubkey_from_cert(cert_path):
    """Load public key from a PEM certificate."""
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data)
    return cert.public_key()

def verify_transcript(transcript_path, receipt_path, cert_path):
    # Load transcript lines
    with open(transcript_path, "r") as f:
        lines = [line.strip() for line in f.readlines()]

    # Load receipt
    with open(receipt_path, "r") as f:
        receipt = json.load(f)

    # Load public key from certificate
    pubkey = load_pubkey_from_cert(cert_path)

    # 1. Recompute transcript hash
    concat = "".join(lines).encode("utf-8")
    recomputed_hash_hex = hashlib.sha256(concat).hexdigest()

    print("Recomputed Hash:", recomputed_hash_hex)
    print("Receipt Hash:   ", receipt["transcript_sha256"])

    # 2. Verify receipt signature
    sig_b64 = receipt["sig"]
    valid = sign.verify_signature(pubkey, bytes.fromhex(recomputed_hash_hex), sig_b64)

    print("Receipt Signature Valid:", valid)

    return valid

if __name__ == "__main__":
    verify_transcript(
        "storage/server_transcript.log",
        "storage/server_receipt.json",
        "certs/server.crt"   # certificate containing public key
    )
