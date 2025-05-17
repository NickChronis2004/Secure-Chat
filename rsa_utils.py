from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# δημιουργία νέου RSA keypair
def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# φόρτωμα public key και RSA encryption
def encrypt_with_rsa(public_key_bytes, data: bytes) -> bytes:
    public_key = RSA.import_key(public_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data)

# φόρτωμα private key και RSA decryption
def decrypt_with_rsa(private_key_bytes, encrypted_data: bytes) -> bytes:
    private_key = RSA.import_key(private_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_data)
