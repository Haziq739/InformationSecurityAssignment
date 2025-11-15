from app.crypto import pki

# Test server certificate
try:
    server_cert = pki.load_and_validate_entity("server")
except ValueError as e:
    print(e)

# Test client certificate
try:
    client_cert = pki.load_and_validate_entity("client")
except ValueError as e:
    print(e)
