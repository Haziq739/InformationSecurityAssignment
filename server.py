# server.py
import socket
import json
from app.storage import db
from app.crypto import pki
from app.crypto import dh as dhlib
from app.crypto import aes as aeslib
from cryptography import x509
import hashlib

HOST = '127.0.0.1'
PORT = 12345

def derive_aes_key_from_shared(shared_bytes: bytes) -> bytes:
    """Derive 16-byte AES-128 key from shared DH secret using SHA256."""
    digest = hashlib.sha256(shared_bytes).digest()
    return digest[:16]

def handle_client(conn, addr):
    print(f"Connected: {addr}")

    # 1️⃣ Certificate Exchange and Validation
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

    conn.send(b"CERT OK")  # ✅ Screenshot: certificate accepted

    # 2️⃣ DH Key Exchange (for registration/login)
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
    # Send server DH public value
    resp = {"type": "dh_server", "B": str(B)}
    conn.send(json.dumps(resp).encode())  # ✅ Screenshot: DH exchange

    shared = dhlib.compute_shared_secret(server_priv, A, p, g)
    aes_key = derive_aes_key_from_shared(shared)

    # 3️⃣ Receive Encrypted Payload (Registration/Login)
    enc_msg = conn.recv(8192).decode()
    try:
        enc_json = json.loads(enc_msg)
        msg_type = enc_json.get("type")
        iv_b64 = enc_json.get("iv")
        ct_b64 = enc_json.get("ct")

        plaintext_bytes = aeslib.aes_cbc_decrypt(iv_b64, ct_b64, aes_key)
        payload = json.loads(plaintext_bytes.decode())  # ✅ Screenshot: decrypted payload

    except Exception as e:
        print("Decryption failed:", e)
        conn.send(b"DECRYPT FAIL")
        conn.close()
        return

    # 4️⃣ Handle Registration
    if msg_type == "register":
        email = payload.get("email")
        username = payload.get("username")
        password = payload.get("password")
        success, info = db.register_user(email, username, password)
        conn.send(info.encode())  # ✅ Screenshot: server response to registration

    # 5️⃣ Handle Login
    elif msg_type == "login":
        email = payload.get("email")
        password = payload.get("password")
        success, info = db.verify_login(email, password)
        conn.send(info.encode())  # ✅ Screenshot: server response to login

        if success:
            # 6️⃣ SESSION KEY DH EXCHANGE (after login)
            dh_session_msg = conn.recv(8192).decode()
            dh_sess_json = json.loads(dh_session_msg)
            if dh_sess_json.get("type") != "dh_session":
                conn.send(b"BAD SESSION DH")
                conn.close()
                return

            p_sess = int(dh_sess_json["p"])
            g_sess = int(dh_sess_json["g"])
            A_sess = int(dh_sess_json["A"])

            server_priv_sess, B_sess = dhlib.generate_private_and_public(p_sess, g_sess)
            resp_sess = {"type": "dh_session_server", "B": str(B_sess)}
            conn.send(json.dumps(resp_sess).encode())  # ✅ Screenshot: DH session exchange

            shared_sess = dhlib.compute_shared_secret(server_priv_sess, A_sess, p_sess, g_sess)
            session_key = derive_aes_key_from_shared(shared_sess)
            print(f"Session key established with {addr}: {session_key.hex()}")  # ✅ Screenshot: session key derived

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
