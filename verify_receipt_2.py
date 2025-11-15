import json, hashlib, shutil
from cryptography.hazmat.primitives import serialization
from app.crypto import sign

def load_pubkey(path):
    with open(path, "rb") as f:
        data = f.read()
    return serialization.load_pem_public_key(data)

def verify_transcript(transcript_path, receipt_path, pubkey_path):
    # Load public key
    pubkey = load_pubkey(pubkey_path)

    # Load transcript lines
    with open(transcript_path, "r") as f:
        lines = [line.strip() for line in f.readlines()]

    # Load receipt
    with open(receipt_path, "r") as f:
        receipt = json.load(f)

    # Recompute hash
    concat = "".join(lines).encode("utf-8")
    recomputed_hash_hex = hashlib.sha256(concat).hexdigest()

    print("Recomputed Hash:", recomputed_hash_hex)
    print("Receipt Hash:   ", receipt["transcript_sha256"])

    # Verify signature
    sig_b64 = receipt["sig"]
    valid = sign.verify_signature(pubkey, bytes.fromhex(recomputed_hash_hex), sig_b64)
    print("Receipt Signature Valid:", valid)

    return valid

def tamper_and_verify(transcript_path, receipt_path, pubkey_path):
    backup_path = transcript_path + ".bak"
    shutil.copyfile(transcript_path, backup_path)

    with open(transcript_path, "r") as f:
        lines = f.readlines()

    lines[-1] = lines[-1].rstrip("\n")
    lines[-1] = lines[-1][:-1] + "X\n"

    with open(transcript_path, "w") as f:
        f.writelines(lines)

    print("\n--- Tampered transcript ---")
    verify_transcript(transcript_path, receipt_path, pubkey_path)

    shutil.move(backup_path, transcript_path)

if __name__ == "__main__":
    print("\n--- Original Verification ---")
    verify_transcript(
        "storage/server_transcript.log",
        "storage/server_receipt.json",
        "certs/server_pub.pem"
    )

    tamper_and_verify(
        "storage/server_transcript.log",
        "storage/server_receipt.json",
        "certs/server_pub.pem"
    )
