import socket
from rsa_utils import encrypt_with_rsa
from encryption_utils import encrypt_message_with_key
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'  # ή LAN IP του server
PORT = 9999

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
print("[*] Connected to server.")

# Step 1: receive public key from server
public_key = client_socket.recv(1024)

# Step 2: generate AES session key
session_key = get_random_bytes(32)
enc_key = encrypt_with_rsa(public_key, session_key)

# Step 3: send encrypted AES key to server
client_socket.sendall(enc_key)
print("[*] AES key sent securely to server.")

# Step 4: send encrypted messages
try:
    while True:
        msg = input("Write secret message (or 'exit'): ")
        if msg.lower() == 'exit':
            break
        enc_msg = encrypt_message_with_key(msg, session_key)
        client_socket.sendall(enc_msg)
finally:
    client_socket.close()
