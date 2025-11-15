import socket
import json
from app.crypto import pki  # PKI validation

HOST = '127.0.0.1'
PORT = 12345

def send_cert(sock):
    with open("certs/client.crt", "rb") as f:
        cert_data = f.read()
    sock.send(cert_data)
    resp = sock.recv(1024)
    if resp != b"CERT OK":
        print("Server rejected certificate")
        return False
    return True

def register(sock, email, username, password):
    data = {"type": "register", "email": email, "username": username, "password": password}
    sock.send(json.dumps(data).encode())
    resp = sock.recv(1024).decode()
    print(resp)

def login(sock, email, password):
    data = {"type": "login", "email": email, "password": password}
    sock.send(json.dumps(data).encode())
    resp = sock.recv(1024).decode()
    print(resp)

def main():
    # Registration
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        if not send_cert(sock):
            return
        email = input("Email: ")
        username = input("Username: ")
        password = input("Password: ")
        register(sock, email, username, password)

    # Login (new connection)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        if not send_cert(sock):
            return
        email = input("Email for login: ")
        password = input("Password: ")
        login(sock, email, password)


if __name__ == "__main__":
    main()
