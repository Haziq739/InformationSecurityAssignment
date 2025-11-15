# client.py
import socket
import json
import time
import os
from app.crypto import pki, dh as dhlib, aes as aeslib, sign
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes

HOST = '127.0.0.1'
PORT = 12345

# storage paths (as you requested)
STORAGE_DIR = "storage"
CLIENT_TRANSCRIPT = os.path.join(STORAGE_DIR, "client_transcript.log")
CLIENT_RECEIPT = os.path.join(STORAGE_DIR, "client_receipt.json")
SERVER_RECEIPT = os.path.join(STORAGE_DIR, "server_receipt.json")
os.makedirs(STORAGE_DIR, exist_ok=True)

def derive_aes_key_from_shared(shared_bytes: bytes) -> bytes:
    digest = hashlib.sha256(shared_bytes).digest()
    return digest[:16]

def fingerprint_of_cert_path(path: str) -> str:
    with open(path, "rb") as f:
        data = f.read()
    cert = x509.load_pem_x509_certificate(data)
    fp = cert.fingerprint(hashes.SHA256())
    return fp.hex()

def send_cert(sock):
    with open("certs/client.crt", "rb") as f:
        cert_data = f.read()
    sock.send(cert_data)
    resp = sock.recv(1024)
    if resp != b"CERT OK":
        print("Server rejected certificate")
        return False
    return True

def do_dh_and_get_key(sock):
    p, g = dhlib.generate_parameters()
    priv, A = dhlib.generate_private_and_public(p, g)
    msg = {"type": "dh_client", "p": str(p), "g": str(g), "A": str(A)}
    sock.send(json.dumps(msg).encode())
    resp = sock.recv(8192).decode()
    resp_json = json.loads(resp)
    if resp_json.get("type") != "dh_server":
        raise RuntimeError("DH failed")
    B = int(resp_json["B"])
    shared = dhlib.compute_shared_secret(priv, B, p, g)
    return derive_aes_key_from_shared(shared)

def do_session_dh(sock):
    p, g = dhlib.generate_parameters()
    priv, A = dhlib.generate_private_and_public(p, g)
    msg = {"type": "dh_session", "p": str(p), "g": str(g), "A": str(A)}
    sock.send(json.dumps(msg).encode())
    resp = sock.recv(8192).decode()
    resp_json = json.loads(resp)
    if resp_json.get("type") != "dh_session_server":
        raise RuntimeError("Session DH failed")
    B = int(resp_json["B"])
    shared = dhlib.compute_shared_secret(priv, B, p, g)
    session_key = derive_aes_key_from_shared(shared)
    print(f"Session key derived: {session_key.hex()}")
    return session_key

def encrypt_and_send_payload(sock, aes_key, payload: dict, msg_type: str):
    plaintext = json.dumps(payload).encode()
    iv_b64, ct_b64 = aeslib.aes_cbc_encrypt(plaintext, aes_key)
    send_json = {"type": msg_type, "iv": iv_b64, "ct": ct_b64}
    sock.send(json.dumps(send_json).encode())
    resp = sock.recv(4096).decode()
    print(resp)

def register_flow():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        if not send_cert(sock):
            return
        aes_key = do_dh_and_get_key(sock)
        email = input("Email: ")
        username = input("Username: ")
        password = input("Password: ")
        payload = {"email": email, "username": username, "password": password}
        encrypt_and_send_payload(sock, aes_key, payload, "register")

def login_flow():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        if not send_cert(sock):
            return
        aes_key = do_dh_and_get_key(sock)
        email = input("Email for login: ")
        password = input("Password: ")
        payload = {"email": email, "password": password}
        encrypt_and_send_payload(sock, aes_key, payload, "login")

        # Session DH
        session_key = do_session_dh(sock)

        # Load client RSA key for signing
        private_key = sign.load_private_key("certs/client.key")

        # load server cert fingerprint (we have server cert locally)
        server_fp = fingerprint_of_cert_path("certs/server.crt")

        seqno = 1

        # in-memory session lines for transcript
        session_lines = []

        while True:
            message = input("Enter chat message (or 'exit'): ")
            if message.lower() == "exit":
                # create client receipt
                concat = "".join(session_lines).encode("utf-8")
                transcript_hash = hashlib.sha256(concat).hexdigest()
                sig_b64 = sign.sign_message(private_key, bytes.fromhex(transcript_hash))
                receipt = {
                    "type": "receipt",
                    "peer": "client",
                    "first_seq": 1 if session_lines else 0,
                    "last_seq": seqno - 1,
                    "transcript_sha256": transcript_hash,
                    "sig": sig_b64
                }
                # save client receipt locally
                with open(CLIENT_RECEIPT, "w", encoding="utf-8") as f:
                    json.dump(receipt, f, indent=2)

                # send receipt to server and wait for server receipt
                sock.send(json.dumps(receipt).encode())
                print("Client receipt sent. Waiting for server receipt...")
                server_reply = sock.recv(8192)
                if server_reply:
                    server_receipt_json = json.loads(server_reply.decode())
                    # verify server receipt signature using server cert
                    server_cert = x509.load_pem_x509_certificate(open("certs/server.crt","rb").read())
                    server_pub = server_cert.public_key()
                    server_hash_hex = server_receipt_json.get("transcript_sha256")
                    server_sig = server_receipt_json.get("sig")
                    ok = sign.verify_signature(server_pub, bytes.fromhex(server_hash_hex), server_sig)
                    print(f"Server receipt signature valid: {ok}")
                    # store server receipt
                    with open(SERVER_RECEIPT, "w", encoding="utf-8") as f:
                        json.dump(server_receipt_json, f, indent=2)
                break

            timestamp = int(time.time() * 1000)
            plaintext = message.encode()
            iv_b64, ct_b64 = aeslib.aes_cbc_encrypt(plaintext, session_key)
            h = hashlib.sha256(f"{seqno}{timestamp}{ct_b64}".encode()).digest()
            sig_b64 = sign.sign_message(private_key, h)
            msg_json = {
                "type": "msg",
                "seqno": seqno,
                "ts": timestamp,
                "ct": ct_b64,
                "iv": iv_b64,
                "sig": sig_b64
            }



            # append this outgoing line to persistent client transcript and in-memory session_lines
            line = f"{seqno}|{timestamp}|{ct_b64}|{sig_b64}|{server_fp}"
            with open(CLIENT_TRANSCRIPT, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            session_lines.append(line)

            sock.send(json.dumps(msg_json).encode())

            # Receive server reply
            reply_bytes = sock.recv(8192)
            if reply_bytes:
                reply_json = json.loads(reply_bytes.decode())
                reply_plain = aeslib.aes_cbc_decrypt(reply_json["iv"], reply_json["ct"], session_key)
                print(f"Server reply: {reply_plain.decode()}")

                # append server's reply line to client transcript and session_lines
                reply_line = f"{reply_json['seqno']}|{reply_json['ts']}|{reply_json['ct']}|{reply_json['sig']}|{server_fp}"
                with open(CLIENT_TRANSCRIPT, "a", encoding="utf-8") as f:
                    f.write(reply_line + "\n")
                session_lines.append(reply_line)

            seqno += 1

def main():
    print("Registration")
    register_flow()
    print("Login")
    login_flow()

if __name__ == "__main__":
    main()
