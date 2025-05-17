from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

def pad(data: bytes) -> bytes:
    padding_length = 16 - len(data) % 16
    return data + bytes([padding_length]) * padding_length

def unpad(data: bytes) -> bytes:
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt_message_with_key(plain_text: str, key: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plain_text.encode()))
    return iv + encrypted

def decrypt_message_with_key(encrypted_data: bytes, key: bytes) -> str:
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted).decode()
