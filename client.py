# client.py (replace your current file)
import socket
import json
from app.crypto import pki
from app.crypto import dh as dhlib
from app.crypto import aes as aeslib
import hashlib
from cryptography import x509

HOST = '127.0.0.1'
PORT = 12345

def derive_aes_key_from_shared(shared_bytes: bytes) -> bytes:
    digest = hashlib.sha256(shared_bytes).digest()
    return digest[:16]

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
    # generate params and A
    p, g = dhlib.generate_parameters()
    priv, A = dhlib.generate_private_and_public(p, g)
    msg = {"type": "dh_client", "p": str(p), "g": str(g), "A": str(A)}
    sock.send(json.dumps(msg).encode())

    # receive server B
    resp = sock.recv(8192).decode()
    resp_json = json.loads(resp)
    if resp_json.get("type") != "dh_server":
        raise RuntimeError("DH failed")
    B = int(resp_json["B"])

    shared = dhlib.compute_shared_secret(priv, B, p, g)
    aes_key = derive_aes_key_from_shared(shared)
    return aes_key

def encrypt_and_send_payload(sock, aes_key, payload: dict, msg_type: str):
    """
    Encrypts a JSON payload, encodes IV + ciphertext as Base64, sends JSON to server.
    """
    plaintext = json.dumps(payload).encode()  # convert dict to bytes
    iv_b64, ct_b64 = aeslib.aes_cbc_encrypt(plaintext, aes_key)
    send_json = {"type": msg_type, "iv": iv_b64, "ct": ct_b64}  # ✅ JSON-safe
    sock.send(json.dumps(send_json).encode())  # send as bytes over socket
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

def main():
    print("Registration")
    register_flow()
    print("Login")
    login_flow()

if __name__ == "__main__":
    main()
