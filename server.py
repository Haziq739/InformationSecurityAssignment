# server.py
import socket
import json
import time
import os
from app.storage import db
from app.crypto import pki, dh as dhlib, aes as aeslib, sign
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import hashlib

HOST = '127.0.0.1'
PORT = 12345

# storage paths (as you requested)
STORAGE_DIR = "storage"
SERVER_TRANSCRIPT = os.path.join(STORAGE_DIR, "server_transcript.log")
SERVER_RECEIPT = os.path.join(STORAGE_DIR, "server_receipt.json")

# ensure storage directory exists
os.makedirs(STORAGE_DIR, exist_ok=True)

def derive_aes_key_from_shared(shared_bytes: bytes) -> bytes:
    return hashlib.sha256(shared_bytes).digest()[:16]

def fingerprint_of_cert(cert: x509.Certificate) -> str:
    # returns hex-encoded SHA256 fingerprint
    fp = cert.fingerprint(hashes.SHA256())
    return fp.hex()

def append_to_file(path: str, line: str):
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def handle_client(conn, addr):
    print(f"Connected: {addr}")

    # Certificate exchange
    client_cert_pem = conn.recv(4096)
    try:
        client_cert = x509.load_pem_x509_certificate(client_cert_pem)
    except Exception as e:
        print(f"Failed to load client certificate: {e}")
        conn.send(b"BAD CERT")
        conn.close()
        return

    ca_cert = pki.load_certificate("certs/root_ca.crt")
    if not pki.validate_certificate(client_cert, ca_cert, expected_cn="client"):
        conn.send(b"BAD CERT")
        conn.close()
        print(f"Rejected client certificate from {addr}")
        return

    conn.send(b"CERT OK")

    client_fp = fingerprint_of_cert(client_cert)

    # DH key for registration/login
    dh_msg = conn.recv(8192).decode()
    dh_json = json.loads(dh_msg)
    if dh_json.get("type") != "dh_client":
        conn.send(b"BAD DH")
        conn.close()
        return
    p = int(dh_json["p"])
    g = int(dh_json["g"])
    A = int(dh_json["A"])
    server_priv, B = dhlib.generate_private_and_public(p, g)
    conn.send(json.dumps({"type": "dh_server", "B": str(B)}).encode())
    shared = dhlib.compute_shared_secret(server_priv, A, p, g)
    aes_key = derive_aes_key_from_shared(shared)

    # Receive registration/login payload
    enc_msg = conn.recv(8192).decode()
    enc_json = json.loads(enc_msg)
    msg_type = enc_json.get("type")
    iv_b64 = enc_json.get("iv")
    ct_b64 = enc_json.get("ct")
    plaintext_bytes = aeslib.aes_cbc_decrypt(iv_b64, ct_b64, aes_key)
    payload = json.loads(plaintext_bytes.decode())

    if msg_type == "register":
        email = payload.get("email")
        username = payload.get("username")
        password = payload.get("password")
        success, info = db.register_user(email, username, password)
        conn.send(info.encode())
    elif msg_type == "login":
        email = payload.get("email")
        password = payload.get("password")
        success, info = db.verify_login(email, password)
        conn.send(info.encode())

        if success:
            # Session DH
            dh_sess_msg = conn.recv(8192).decode()
            dh_sess_json = json.loads(dh_sess_msg)
            p_sess = int(dh_sess_json["p"])
            g_sess = int(dh_sess_json["g"])
            A_sess = int(dh_sess_json["A"])
            server_priv_sess, B_sess = dhlib.generate_private_and_public(p_sess, g_sess)
            conn.send(json.dumps({"type": "dh_session_server", "B": str(B_sess)}).encode())
            shared_sess = dhlib.compute_shared_secret(server_priv_sess, A_sess, p_sess, g_sess)
            session_key = derive_aes_key_from_shared(shared_sess)
            print(f"Session key established with {addr}: {session_key.hex()}")

            # Load client RSA key for verifying client messages (public key from cert)
            client_pub_key = client_cert.public_key()

            # Load server RSA key for signing replies
            server_private_key = sign.load_private_key("certs/server.key")

            # in-memory session transcript lines for this session
            session_lines = []  # will hold strings: seqno|ts|ct|sig|peer_fp

            last_seqno = 0
            while True:
                try:
                    msg_bytes = conn.recv(8192)
                    if not msg_bytes:
                        # client closed
                        break

                    msg_json = json.loads(msg_bytes.decode())

                    # handle special 'receipt' message from client (session closure)
                    if msg_json.get("type") == "receipt":
                        # client sent its receipt; verify and reply with server receipt
                        client_receipt = msg_json
                        # verify client's signature on their transcript hash
                        client_transcript_hash_hex = client_receipt.get("transcript_sha256")
                        client_sig_b64 = client_receipt.get("sig")
                        # verify client's signature using their cert public key
                        valid = sign.verify_signature(client_pub_key, bytes.fromhex(client_transcript_hash_hex), client_sig_b64)
                        print(f"Client receipt signature valid: {valid}")

                        # Now compute server's own transcript hash for this session and sign it
                        concat = "".join(session_lines).encode("utf-8")
                        server_transcript_hash = hashlib.sha256(concat).hexdigest()
                        server_sig_b64 = sign.sign_message(server_private_key, bytes.fromhex(server_transcript_hash))

                        # create server receipt JSON
                        receipt = {
                            "type": "receipt",
                            "peer": "server",
                            "first_seq": 1 if session_lines else 0,
                            "last_seq": last_seqno,
                            "transcript_sha256": server_transcript_hash,
                            "sig": server_sig_b64
                        }

                        # save server transcript (already appended lines were written), write receipt file
                        with open(SERVER_RECEIPT, "w", encoding="utf-8") as f:
                            json.dump(receipt, f, indent=2)

                        # send server receipt back to client
                        conn.send(json.dumps(receipt).encode())
                        print("Server receipt created and sent to client.")
                        # keep serving? break to close
                        break

                    if msg_json["type"] != "msg":
                        continue

                    seqno = msg_json["seqno"]
                    if seqno <= last_seqno:
                        print("Replay detected, ignoring message")
                        continue
                    last_seqno = seqno
                    ts = msg_json["ts"]
                    ct_b64 = msg_json["ct"]
                    iv_b64 = msg_json["iv"]
                    sig_b64 = msg_json["sig"]

                    h = hashlib.sha256(f"{seqno}{ts}{ct_b64}".encode()).digest()
                    if not sign.verify_signature(client_pub_key, h, sig_b64):
                        print("Signature verification failed")
                        continue

                    plaintext = aeslib.aes_cbc_decrypt(iv_b64, ct_b64, session_key)
                    print(f"Received message [{seqno}]: {plaintext.decode()}")

                    # Append this line to server's persistent transcript and in-memory session_lines
                    line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{client_fp}"
                    append_to_file(SERVER_TRANSCRIPT, line)
                    session_lines.append(line)

                    # Automatic reply to client
                    reply_text = f"Server received: {plaintext.decode()}"
                    iv_r, ct_r = aeslib.aes_cbc_encrypt(reply_text.encode(), session_key)
                    h_r = hashlib.sha256(f"{seqno}{ts}{ct_r}".encode()).digest()
                    sig_r = sign.sign_message(server_private_key, h_r)
                    reply_json = {
                        "type": "msg",
                        "seqno": seqno,
                        "ts": ts,
                        "ct": ct_r,
                        "iv": iv_r,
                        "sig": sig_r
                    }

                    # append reply line to transcript and in-memory session lines (peer fingerprint = client_fp)
                    reply_line = f"{seqno}|{ts}|{ct_r}|{sig_r}|{client_fp}"
                    append_to_file(SERVER_TRANSCRIPT, reply_line)
                    session_lines.append(reply_line)

                    conn.send(json.dumps(reply_json).encode())

                except Exception as e:
                    print("Error handling message:", e)
                    break
    else:
        conn.send(b"UNKNOWN")

    conn.close()

def main():
    db.create_users_table()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            handle_client(conn, addr)

if __name__ == "__main__":
    main()
