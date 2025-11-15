import json
import hashlib
from app.crypto import sign
from cryptography import x509

TRANSCRIPT_FILE = "storage/server_transcript.log"
CLIENT_CERT_FILE = "certs/client.crt"  # public key from client certificate

def load_client_pubkey(cert_path):
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data)
    return cert.public_key()

def verify_transcript_messages(transcript_path, pubkey):
    all_valid = True
    with open(transcript_path, "r") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        seqno, ts, ct_b64, sig_b64, peer_fp = line.split("|")
        # recompute SHA-256 hash
        h = hashlib.sha256(f"{seqno}{ts}{ct_b64}".encode()).digest()
        valid = sign.verify_signature(pubkey, h, sig_b64)
        print(f"Message seq {seqno} signature valid: {valid}")
        if not valid:
            all_valid = False
    return all_valid

if __name__ == "__main__":
    pubkey = load_client_pubkey(CLIENT_CERT_FILE)
    result = verify_transcript_messages(TRANSCRIPT_FILE, pubkey)
    if result:
        print("All messages are valid ✅")
    else:
        print("Some messages failed verification ❌")
