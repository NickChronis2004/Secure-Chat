import socket
from rsa_utils import generate_rsa_keypair, decrypt_with_rsa
from encryption_utils import decrypt_message_with_key

HOST = '0.0.0.0'
PORT = 9999

# generate RSA keys
private_key, public_key = generate_rsa_keypair()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)
print(f"[+] Listening on port {PORT}...")

conn, addr = server_socket.accept()
print(f"[+] Connection from {addr}")

# Step 1: send public key to client
conn.sendall(public_key)

# Step 2: receive encrypted AES key from client
enc_aes_key = conn.recv(512)
session_key = decrypt_with_rsa(private_key, enc_aes_key)
print(f"[+] AES session key received and decrypted.")

# Step 3: receive encrypted messages
while True:
    data = conn.recv(4096)
    if not data:
        break
    try:
        decrypted = decrypt_message_with_key(data, session_key)
        print(f"[Decrypted Message]: {decrypted}")
    except Exception as e:
        print("[!] Error decrypting:", str(e))

conn.close()
server_socket.close()
