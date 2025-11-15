import socket
import json
from app.storage import db
from app.crypto import pki  # PKI validation
from cryptography import x509

HOST = '127.0.0.1'
PORT = 12345

def handle_client(conn, addr):
    print(f"Connected: {addr}")

    # 1️⃣ Receive client certificate
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

    # 2️⃣ Receive registration/login JSON
    try:
        msg = conn.recv(4096).decode()
        data = json.loads(msg)

        if data["type"] == "register":
            success, info = db.register_user(data["email"], data["username"], data["password"])
            conn.send(info.encode())
        elif data["type"] == "login":
            success, info = db.verify_login(data["email"], data["password"])
            conn.send(info.encode())
        else:
            conn.send(b"Unknown message type")
    except Exception as e:
        print(f"Error handling client message: {e}")
        conn.send(b"Error")
    
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
