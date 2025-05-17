# Secure Chat – RSA & AES Encrypted Communication

This is a simple example of secure communication using RSA for key exchange and AES for encrypted messaging.

## Features
- RSA key generation (2048-bit)
- AES-CBC encryption/decryption
- Secure key exchange
- Real-time message encryption

## Usage

### 1. Install dependencies
pip install -r requirements.txt

## 2. Run Server
python server.py

Type messages in the client. They are sent encrypted to the server and decrypted in real-time.
