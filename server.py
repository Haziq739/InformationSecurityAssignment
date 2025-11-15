# server.py
import socket
import json
import time
from app.storage import db
from app.crypto import pki, dh as dhlib, aes as aeslib, sign
from cryptography import x509
import hashlib

HOST = '127.0.0.1'
PORT = 12345

def derive_aes_key_from_shared(shared_bytes: bytes) -> bytes:
    return hashlib.sha256(shared_bytes).digest()[:16]

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

            # Load client RSA key for verifying client messages
            client_pub_key = client_cert.public_key()

            # Load server RSA key for signing replies
            server_private_key = sign.load_private_key("certs/server.key")

            last_seqno = 0
            while True:
                try:
                    msg_bytes = conn.recv(8192)
                    if not msg_bytes:
                        break
                    msg_json = json.loads(msg_bytes.decode())
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
